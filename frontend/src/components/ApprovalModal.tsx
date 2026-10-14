/**
 * ApprovalModal — Release approval/rejection form that triggers attestation creation.
 *
 * Attestation flow from the frontend perspective:
 *
 *   1. User clicks "Approve" or "Reject" on the deployment card
 *   2. This modal opens, collecting a reason (text) and optional documentation (file)
 *   3. On submit, the frontend sends a multipart form to POST /api/attest containing:
 *      - imageRef: the container image reference (without tag/digest)
 *      - digest: the image's sha256 digest (resolved from the tag if needed)
 *      - approved: "true" or "false"
 *      - reason: the free-text reason for the decision
 *      - idToken: the user's Keycloak ID token (critical — see below)
 *      - documentation: optional file attachment
 *   4. The backend builds an in-toto predicate, writes it to a temp file, and invokes
 *      cosign attest with the user's ID token as --identity-token
 *   5. Fulcio issues a short-lived certificate with the user's email, cosign signs the
 *      attestation, and pushes it as a new layer on the image's .att tag in Quay
 *
 * Why the idToken is sent in the form body (not just the Authorization header):
 *
 *   The Authorization header carries the access_token, which the backend uses to
 *   authenticate the API request (validate the JWT, extract the username). But for
 *   signing, cosign needs the id_token — a different JWT that Fulcio accepts as proof
 *   of identity. The id_token contains the user's email in its claims, which Fulcio
 *   embeds as the certificate's Subject Alternative Name (SAN). This is how the signed
 *   attestation gets cryptographically bound to the user's identity.
 *
 * Digest resolution:
 *
 *   OpenShift deployments often reference images by tag (e.g. :latest) rather than
 *   by digest. But cosign attest requires the exact digest (sha256:...) to attach
 *   the attestation to. We resolve the digest by looking up the tag in the image
 *   tags list fetched from the Quay API. If the tag doesn't exist in Quay (e.g.
 *   the image was deleted), attestation fails with a clear error.
 */
import React, { useState } from 'react';
import {
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Button,
  Form,
  FormGroup,
  TextArea,
  FileUpload,
  Alert,
  Spinner,
  ExpandableSection,
} from '@patternfly/react-core';
import { DeploymentInfo, AttestResult, Tag } from '../types';

interface ApprovalModalProps {
  isOpen: boolean;
  deployment: DeploymentInfo | null;
  isApproval: boolean;
  token: string | null;   // Keycloak access_token — used as Bearer for API authentication
  idToken: string | null;  // Keycloak id_token — forwarded to cosign as the signing identity
  tags: Tag[];             // All known image tags — used to resolve digest from tag name
  onClose: () => void;
  onResult: (result: AttestResult) => void;
}

export const ApprovalModal: React.FC<ApprovalModalProps> = ({
  isOpen,
  deployment,
  isApproval,
  token,
  idToken,
  tags,
  onClose,
  onResult,
}) => {
  const [reason, setReason] = useState('');
  const [filename, setFilename] = useState('');
  const [fileValue, setFileValue] = useState<File | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);

  const action = isApproval ? 'approval' : 'rejection';

  // Resolve the image digest from the deployment's tag. Deployments in OpenShift
  // typically reference images by tag (e.g. :latest), but cosign attest needs the
  // immutable digest (sha256:...) to attach the attestation to the correct image.
  function resolveDigest(): string {
    if (!deployment) return '';
    // If the deployment already has a digest (image referenced as image@sha256:...), use it
    if (deployment.digest) return deployment.digest;
    // Otherwise, look up the tag in the Quay tags list to find its manifest digest
    if (deployment.tag) {
      const match = tags.find((t) => t.name === deployment.tag);
      if (match) {
        console.log('[attest] Resolved digest from tag %s: %s', deployment.tag, match.manifest_digest);
        return match.manifest_digest;
      }
    }
    return '';
  }

  const digest = resolveDigest();
  const digestShort = digest
    ? digest.startsWith('sha256:')
      ? `sha256:${digest.slice(7, 19)}...`
      : digest.slice(0, 16) + '...'
    : deployment?.tag || '';

  const handleSubmit = async () => {
    // Both tokens are required: access_token for API auth, id_token for signing identity
    if (!deployment || !token || !idToken) {
      setError('Missing authentication tokens. Please log in again.');
      return;
    }
    if (!reason.trim()) {
      setError('Please provide a reason.');
      return;
    }
    if (!digest) {
      setError(`Cannot resolve image digest for tag "${deployment.tag}". The image may not exist in Quay yet.`);
      return;
    }

    setIsLoading(true);
    setError(null);
    setErrorDetail(null);

    // Strip the tag/digest from the image reference — the backend will use imageRef + digest
    const imageBase = deployment.image.split('@')[0].split(':')[0];

    console.log('[attest] Submitting attestation:', {
      imageRef: imageBase,
      digest,
      approved: isApproval,
      hasFile: !!fileValue,
    });

    try {
      // Build multipart form data. The idToken is sent as a form field (not a header)
      // because the Authorization header is already used for the access_token.
      // The backend extracts the idToken from the form and passes it to cosign
      // via --identity-token for Fulcio certificate issuance.
      const formData = new FormData();
      formData.append('imageRef', imageBase);
      formData.append('digest', digest);
      formData.append('approved', String(isApproval));
      formData.append('reason', reason);
      formData.append('idToken', idToken);  // Critical: this is the user's signing identity

      if (fileValue) {
        formData.append('documentation', fileValue);
      }

      console.log('[attest] Sending POST /api/attest');
      const resp = await fetch('/api/attest', {
        method: 'POST',
        headers: {
          // access_token for API authentication — the backend validates this JWT
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      if (!resp.ok && resp.headers.get('content-type')?.includes('application/json') === false) {
        const text = await resp.text();
        setError(`Server error (${resp.status})`);
        setErrorDetail(text);
        return;
      }

      const result: AttestResult = await resp.json();
      console.log('[attest] Result:', result);

      if (result.success) {
        onResult(result);
        handleClose();
      } else {
        // Show the cosign error message and stderr/stdout for debugging
        setError(result.message || 'Attestation failed');
        const details = [result.stderr, result.stdout].filter(Boolean).join('\n');
        if (details) {
          setErrorDetail(details);
        }
      }
    } catch (err) {
      console.error('[attest] Error:', err);
      setError(`Request failed: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setReason('');
    setFilename('');
    setFileValue(undefined);
    setError(null);
    setErrorDetail(null);
    setIsLoading(false);
    onClose();
  };

  if (!deployment) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      aria-label={`Release ${action} form`}
      variant="medium"
    >
      <ModalHeader
        title={`Release ${action.charAt(0).toUpperCase() + action.slice(1)}`}
        description={`Reason for ${action} of current preprod image ${digestShort}`}
      />
      <ModalBody>
        <Form>
          {error && (
            <FormGroup>
              <Alert variant="danger" isInline title="Error">
                <p>{error}</p>
                {errorDetail && (
                  <ExpandableSection toggleText="Show details">
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.85em', marginTop: '0.5rem' }}>
                      {errorDetail}
                    </pre>
                  </ExpandableSection>
                )}
              </Alert>
            </FormGroup>
          )}

          <FormGroup label="Reason" isRequired fieldId="reason">
            <TextArea
              id="reason"
              value={reason}
              onChange={(_event, val) => setReason(val)}
              placeholder={`Enter the reason for ${action}...`}
              rows={5}
              isDisabled={isLoading}
            />
          </FormGroup>

          <FormGroup
            label="Accompanying Documentation"
            fieldId="documentation"
          >
            <FileUpload
              id="documentation"
              value={fileValue}
              filename={filename}
              onFileInputChange={(_event, file) => {
                setFileValue(file);
                setFilename(file.name);
                console.log('[attest] File selected:', file.name, file.size, 'bytes');
              }}
              onClearClick={() => {
                setFileValue(undefined);
                setFilename('');
              }}
              browseButtonText="Browse..."
              isDisabled={isLoading}
            />
          </FormGroup>
        </Form>

        {isLoading && (
          <div style={{ textAlign: 'center', padding: '1rem' }}>
            <Spinner size="lg" />
            <p style={{ marginTop: '0.5rem' }}>
              Attesting image... This may take a moment.
            </p>
          </div>
        )}
      </ModalBody>
      <ModalFooter>
        <Button
          variant={isApproval ? 'primary' : 'danger'}
          onClick={handleSubmit}
          isDisabled={isLoading || !reason.trim()}
          isLoading={isLoading}
        >
          Submit
        </Button>
        <Button
          variant="link"
          onClick={handleClose}
          isDisabled={isLoading}
        >
          Cancel
        </Button>
      </ModalFooter>
    </Modal>
  );
};
