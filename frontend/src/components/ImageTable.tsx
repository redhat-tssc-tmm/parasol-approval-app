import React from 'react';
import {
  Card,
  CardBody,
  CardTitle,
  Label,
  Spinner,
  Tooltip,
  Popover,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import {
  CheckCircleIcon,
  TimesCircleIcon,
  OutlinedQuestionCircleIcon,
  PaperclipIcon,
  DownloadIcon,
} from '@patternfly/react-icons';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import { Tag, DeploymentInfo, ReleaseStatus } from '../types';

interface ImageTableProps {
  tags: Tag[];
  repository: string;
  namespace: string;
  quayURL: string;
  deployments: DeploymentInfo[];
  releaseStatuses: Record<string, ReleaseStatus>;
  onInspect: (namespace: string, repository: string, tag: string, digest: string) => void;
}

function isDeployed(tag: Tag, deployments: DeploymentInfo[]): boolean {
  return deployments.some(
    (d) => d.digest === tag.manifest_digest || d.tag === tag.name
  );
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-';
  try {
    const d = new Date(dateStr);
    return d.toLocaleString();
  } catch {
    return dateStr;
  }
}

function shortenDigest(digest: string): string {
  if (!digest) return '-';
  if (digest.startsWith('sha256:')) {
    return `sha256:${digest.slice(7, 19)}...`;
  }
  return digest.slice(0, 16) + '...';
}

function formatLocalDate(dateStr?: string): string {
  if (!dateStr) return '?';
  try {
    return new Date(dateStr).toLocaleString();
  } catch {
    return dateStr;
  }
}

function truncateReason(reason?: string, maxLen = 80): string {
  if (!reason) return '';
  const firstLine = reason.split('\n')[0];
  if (firstLine.length <= maxLen) return firstLine;
  return firstLine.slice(0, maxLen) + '...';
}

function formatFileSize(base64Data: string): string {
  try {
    const bytes = atob(base64Data).length;
    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} bytes`;
  } catch {
    return '?';
  }
}

function downloadBase64File(base64Data: string, filename: string) {
  try {
    const byteChars = atob(base64Data);
    const byteNumbers = new Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) {
      byteNumbers[i] = byteChars.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('[download] Failed to decode file:', err);
  }
}

function ReleasePopoverBody({ status }: { status: ReleaseStatus }) {
  const isApproved = status.status === 'approved';
  return (
    <DescriptionList isCompact isHorizontal>
      <DescriptionListGroup>
        <DescriptionListTerm>Status</DescriptionListTerm>
        <DescriptionListDescription>
          <Label color={isApproved ? 'green' : 'red'} icon={isApproved ? <CheckCircleIcon /> : <TimesCircleIcon />}>
            {isApproved ? 'Approved' : 'Rejected'}
          </Label>
        </DescriptionListDescription>
      </DescriptionListGroup>
      <DescriptionListGroup>
        <DescriptionListTerm>Signer</DescriptionListTerm>
        <DescriptionListDescription>{status.approver || '?'}</DescriptionListDescription>
      </DescriptionListGroup>
      <DescriptionListGroup>
        <DescriptionListTerm>Date</DescriptionListTerm>
        <DescriptionListDescription>{formatLocalDate(status.date)}</DescriptionListDescription>
      </DescriptionListGroup>
      {status.reason && (
        <DescriptionListGroup>
          <DescriptionListTerm>Reason</DescriptionListTerm>
          <DescriptionListDescription>
            <div style={{ whiteSpace: 'pre-wrap', maxWidth: '300px', maxHeight: '150px', overflowY: 'auto' }}>
              {status.reason}
            </div>
          </DescriptionListDescription>
        </DescriptionListGroup>
      )}
      {status.docsFilename && status.docsBase64 && (
        <DescriptionListGroup>
          <DescriptionListTerm>Attachment</DescriptionListTerm>
          <DescriptionListDescription>
            <PaperclipIcon /> {status.docsFilename} ({formatFileSize(status.docsBase64)})
            <br />
            <Button
              variant="link"
              isInline
              icon={<DownloadIcon />}
              onClick={() => downloadBase64File(status.docsBase64!, status.docsFilename!)}
              style={{ marginTop: '0.25rem' }}
            >
              Download
            </Button>
          </DescriptionListDescription>
        </DescriptionListGroup>
      )}
    </DescriptionList>
  );
}

function ReleaseIcon({ status }: { status?: ReleaseStatus }) {
  if (!status || status.status === 'checking') {
    return <Spinner size="sm" />;
  }

  switch (status.status) {
    case 'approved':
    case 'rejected': {
      const isApproved = status.status === 'approved';
      const Icon = isApproved ? CheckCircleIcon : TimesCircleIcon;
      const color = isApproved
        ? 'var(--pf-t--global--color--status--success--default)'
        : 'var(--pf-t--global--color--status--danger--default)';
      return (
        <Popover
          headerContent={isApproved ? 'Release Approved' : 'Release Rejected'}
          bodyContent={<ReleasePopoverBody status={status} />}
          position="right"
          maxWidth="450px"
        >
          <span style={{ cursor: 'pointer' }}>
            <Icon color={color} />
            {status.docsFilename && (
              <PaperclipIcon style={{ marginLeft: '0.3rem', opacity: 0.7 }} />
            )}
          </span>
        </Popover>
      );
    }
    case 'none':
      return (
        <Tooltip content="No release attestation">
          <OutlinedQuestionCircleIcon color="var(--pf-t--global--color--status--info--default)" />
        </Tooltip>
      );
    case 'error':
      return (
        <Tooltip content={`Error: ${status.error || 'unknown'}`}>
          <OutlinedQuestionCircleIcon color="var(--pf-t--global--color--status--warning--default)" />
        </Tooltip>
      );
    default:
      return null;
  }
}

export const ImageTable: React.FC<ImageTableProps> = ({
  tags,
  repository,
  namespace,
  quayURL,
  deployments,
  releaseStatuses,
  onInspect,
}) => {
  if (!tags || tags.length === 0) {
    return (
      <Card>
        <CardTitle>
          Images: {namespace}/{repository}
        </CardTitle>
        <CardBody>No image tags found.</CardBody>
      </Card>
    );
  }

  return (
    <Card>
      <CardTitle>
        Images: {namespace}/{repository}
      </CardTitle>
      <CardBody>
        <Table aria-label="Image tags" variant="compact">
          <Thead>
            <Tr>
              <Th>Tag</Th>
              <Th>Digest</Th>
              <Th>Last Modified</Th>
              <Th style={{ textAlign: 'center' }}>Release</Th>
              <Th>Status</Th>
            </Tr>
          </Thead>
          <Tbody>
            {tags.map((tag) => {
              const deployed = isDeployed(tag, deployments);
              const releaseStatus = releaseStatuses[tag.manifest_digest];
              return (
                <Tr key={tag.name} isRowSelected={deployed}>
                  <Td>
                    <Tooltip content="Inspect Attestations">
                      <a
                        href="#"
                        onClick={(e) => {
                          e.preventDefault();
                          onInspect(namespace, repository, tag.name, tag.manifest_digest);
                        }}
                      >
                        {tag.name}
                      </a>
                    </Tooltip>
                  </Td>
                  <Td>
                    <code>{shortenDigest(tag.manifest_digest)}</code>
                  </Td>
                  <Td>{formatDate(tag.last_modified)}</Td>
                  <Td style={{ textAlign: 'center' }}>
                    <ReleaseIcon status={releaseStatus} />
                  </Td>
                  <Td>
                    {deployed && (
                      <Label color="green">Deployed in preprod</Label>
                    )}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </CardBody>
    </Card>
  );
};
