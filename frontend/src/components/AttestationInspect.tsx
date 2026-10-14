import React, { useState, useEffect, useCallback } from 'react';
import {
  PageSection,
  Title,
  Button,
  Card,
  CardBody,
  CardTitle,
  Bullseye,
  Spinner,
  Label,
  Alert,
  Split,
  SplitItem,
  Popover,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import {
  ArrowLeftIcon,
  CheckCircleIcon,
  TimesCircleIcon,
  InfoCircleIcon,
} from '@patternfly/react-icons';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import { JsonTreeView } from './JsonTreeView';

interface CertInfo {
  identity?: string;
  issuer?: string;
  oidcIssuer?: string;
  validFrom?: string;
  validTo?: string;
}

interface AttestationSummary {
  index: number;
  predicateType: string;
  date: string;
  signer: string;
  buildType?: string;
  approved?: boolean;
  cert?: CertInfo;
}

interface AttestationDetail {
  summary: AttestationSummary;
  payload: Record<string, unknown>;
}

interface AttestationInspectProps {
  namespace: string;
  repository: string;
  tag: string;
  digest: string;
  token: string;
  onBack: () => void;
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-';
  try {
    return new Date(dateStr).toLocaleString();
  } catch {
    return dateStr;
  }
}

function shortenType(predicateType: string): string {
  if (predicateType.includes('parasol-insurance.com/releases')) {
    return 'Release Approval';
  }
  if (predicateType.includes('slsa.dev/provenance')) {
    return 'SLSA Provenance';
  }
  const parts = predicateType.split('/');
  return parts[parts.length - 1] || predicateType;
}

function shortenDigest(digest: string): string {
  if (digest.startsWith('sha256:')) {
    return `sha256:${digest.slice(7, 19)}...`;
  }
  return digest.slice(0, 16) + '...';
}

export const AttestationInspect: React.FC<AttestationInspectProps> = ({
  namespace,
  repository,
  tag,
  digest,
  token,
  onBack,
}) => {
  const [summaries, setSummaries] = useState<AttestationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [detail, setDetail] = useState<AttestationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchSummaries = useCallback(async () => {
    setLoading(true);
    setError(null);
    console.log('[inspect] Fetching attestations for %s/%s@%s', namespace, repository, digest);

    try {
      const resp = await fetch(`/api/attestations/${namespace}/${digest}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const data: AttestationSummary[] = await resp.json();
      console.log('[inspect] Got %d attestations', data.length);
      setSummaries(data);
      if (data.length > 0) {
        setSelectedIndex(0);
        fetchDetail(0);
      }
    } catch (err) {
      console.error('[inspect] Failed to fetch attestations:', err);
      setError(`${err}`);
    } finally {
      setLoading(false);
    }
  }, [namespace, digest, token]);

  const fetchDetail = async (index: number) => {
    setDetailLoading(true);
    setDetail(null);
    console.log('[inspect] Fetching detail for attestation %d', index);

    try {
      const resp = await fetch(`/api/attestations/${namespace}/${digest}/${index}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const data: AttestationDetail = await resp.json();
      console.log('[inspect] Got detail for attestation %d', index);
      setDetail(data);
    } catch (err) {
      console.error('[inspect] Failed to fetch detail:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    fetchSummaries();
  }, [fetchSummaries]);

  const handleRowClick = (index: number) => {
    setSelectedIndex(index);
    fetchDetail(index);
  };

  return (
    <>
      <PageSection>
        <Split hasGutter>
          <SplitItem>
            <Button variant="plain" onClick={onBack} aria-label="Back">
              <ArrowLeftIcon /> Back
            </Button>
          </SplitItem>
          <SplitItem isFilled>
            <Title headingLevel="h1" size="xl">
              Inspect Attestations for {namespace}/{repository}:{tag}
            </Title>
            <span style={{ opacity: 0.7 }}>Digest: {shortenDigest(digest)}</span>
          </SplitItem>
        </Split>
      </PageSection>

      <PageSection>
        {loading ? (
          <Bullseye>
            <Spinner size="xl" />
          </Bullseye>
        ) : error ? (
          <Alert variant="danger" title="Failed to load attestations">
            {error}
          </Alert>
        ) : summaries.length === 0 ? (
          <Alert variant="info" title="No attestations found">
            This image has no attestations attached.
          </Alert>
        ) : (
          <>
            <Card style={{ marginBottom: '1rem' }}>
              <CardTitle>Attestations ({summaries.length})</CardTitle>
              <CardBody>
                <Table aria-label="Attestations" variant="compact">
                  <Thead>
                    <Tr>
                      <Th>Type</Th>
                      <Th>Predicate Type URI</Th>
                      <Th>Date</Th>
                      <Th>Signer</Th>
                      <Th>Status</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {summaries.map((s) => (
                      <Tr
                        key={s.index}
                        isRowSelected={s.index === selectedIndex}
                        isClickable
                        onRowClick={() => handleRowClick(s.index)}
                        style={{ cursor: 'pointer' }}
                      >
                        <Td>
                          <strong>{shortenType(s.predicateType)}</strong>
                        </Td>
                        <Td>
                          <code style={{ fontSize: '0.8em' }}>{s.predicateType}</code>
                        </Td>
                        <Td>{formatDate(s.date)}</Td>
                        <Td>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                            <span>
                              {s.signer || '-'}
                              {s.buildType && (
                                <div style={{ fontSize: '0.8em', opacity: 0.7 }}>
                                  {s.buildType.split('/').pop()}
                                </div>
                              )}
                            </span>
                            {s.cert && (
                              <Popover
                                headerContent="Certificate Details"
                                bodyContent={
                                  <DescriptionList isCompact isHorizontal>
                                    {s.cert.identity && (
                                      <DescriptionListGroup>
                                        <DescriptionListTerm>Identity</DescriptionListTerm>
                                        <DescriptionListDescription style={{ wordBreak: 'break-all' }}>
                                          {s.cert.identity}
                                        </DescriptionListDescription>
                                      </DescriptionListGroup>
                                    )}
                                    {s.cert.issuer && (
                                      <DescriptionListGroup>
                                        <DescriptionListTerm>Cert Issuer</DescriptionListTerm>
                                        <DescriptionListDescription>{s.cert.issuer}</DescriptionListDescription>
                                      </DescriptionListGroup>
                                    )}
                                    {s.cert.oidcIssuer && (
                                      <DescriptionListGroup>
                                        <DescriptionListTerm>OIDC Issuer</DescriptionListTerm>
                                        <DescriptionListDescription style={{ wordBreak: 'break-all' }}>
                                          {s.cert.oidcIssuer}
                                        </DescriptionListDescription>
                                      </DescriptionListGroup>
                                    )}
                                    {s.cert.validFrom && (
                                      <DescriptionListGroup>
                                        <DescriptionListTerm>Valid</DescriptionListTerm>
                                        <DescriptionListDescription>
                                          {formatDate(s.cert.validFrom || '')} — {formatDate(s.cert.validTo || '')}
                                        </DescriptionListDescription>
                                      </DescriptionListGroup>
                                    )}
                                  </DescriptionList>
                                }
                                position="right"
                                maxWidth="500px"
                              >
                                <InfoCircleIcon
                                  style={{ cursor: 'pointer', opacity: 0.6 }}
                                />
                              </Popover>
                            )}
                          </span>
                        </Td>
                        <Td>
                          {s.approved === true && (
                            <Label color="green" icon={<CheckCircleIcon />}>
                              Approved
                            </Label>
                          )}
                          {s.approved === false && (
                            <Label color="red" icon={<TimesCircleIcon />}>
                              Rejected
                            </Label>
                          )}
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </CardBody>
            </Card>

            <Card>
              <CardTitle>
                Attestation Detail
                {selectedIndex !== null && summaries[selectedIndex] && (
                  <span style={{ fontWeight: 'normal', fontSize: '0.85em', marginLeft: '1rem', opacity: 0.7 }}>
                    {shortenType(summaries[selectedIndex].predicateType)} — {formatDate(summaries[selectedIndex].date)}
                  </span>
                )}
              </CardTitle>
              <CardBody>
                {detailLoading ? (
                  <Bullseye style={{ padding: '2rem' }}>
                    <Spinner size="lg" />
                  </Bullseye>
                ) : detail ? (
                  <JsonTreeView data={detail.payload} />
                ) : (
                  <p style={{ opacity: 0.5 }}>Select an attestation above to view its details.</p>
                )}
              </CardBody>
            </Card>
          </>
        )}
      </PageSection>
    </>
  );
};
