import React, { useState, useEffect, useCallback } from 'react';
import {
  Page,
  PageSection,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  ToolbarGroup,
  Button,
  Alert,
  AlertGroup,
  AlertVariant,
  Bullseye,
  Spinner,
  Title,
  Label,
  Masthead,
  MastheadMain,
  MastheadBrand,
  MastheadContent,
  EmptyState,
  EmptyStateBody,
  Card,
  CardTitle,
  CardBody,
} from '@patternfly/react-core';
import { SunIcon, MoonIcon } from '@patternfly/react-icons';
import { useAuth } from './hooks/useAuth';
import { useWebSocket } from './hooks/useWebSocket';
import { ImageTable } from './components/ImageTable';
import { DeploymentCard } from './components/DeploymentCard';
import { ApprovalModal } from './components/ApprovalModal';
import { AttestationInspect } from './components/AttestationInspect';
import { ImageInfo, DeploymentInfo, AttestResult, Tag, WSMessage, ReleaseStatus } from './types';

interface InspectView {
  namespace: string;
  repository: string;
  tag: string;
  digest: string;
}

interface AlertItem {
  key: number;
  title: string;
  variant: AlertVariant;
}

let alertKey = 0;

const REPO_FILTER = 'secured';

const App: React.FC = () => {
  const {
    authenticated,
    user,
    token,
    idToken,
    loading: authLoading,
    error: authError,
    logout,
  } = useAuth();

  const [images, setImages] = useState<ImageInfo[]>([]);
  const [deployments, setDeployments] = useState<DeploymentInfo[]>([]);
  const [loadingData, setLoadingData] = useState(false);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [releaseStatuses, setReleaseStatuses] = useState<Record<string, ReleaseStatus>>({});
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('parasol-theme');
    return saved ? saved === 'dark' : true;
  });

  const [inspectView, setInspectView] = useState<InspectView | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalDeployment, setModalDeployment] = useState<DeploymentInfo | null>(null);
  const [modalIsApproval, setModalIsApproval] = useState(true);

  const quayURL = import.meta.env.VITE_QUAY_URL || '';

  useEffect(() => {
    const el = document.documentElement;
    if (darkMode) {
      el.classList.add('pf-v6-theme-dark');
    } else {
      el.classList.remove('pf-v6-theme-dark');
    }
    localStorage.setItem('parasol-theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const addAlert = useCallback((title: string, variant: AlertVariant) => {
    const key = alertKey++;
    setAlerts((prev) => [...prev, { key, title, variant }]);
    setTimeout(() => {
      setAlerts((prev) => prev.filter((a) => a.key !== key));
    }, 15000);
  }, []);

  const fetchData = useCallback(async () => {
    if (!token || !user) return;
    setLoadingData(true);
    console.log('[app] Fetching data for user:', user.preferred_username);

    try {
      const [imagesResp, deploymentsResp] = await Promise.all([
        fetch(`/api/images/${user.preferred_username}`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`/api/deployments/${user.preferred_username}`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      if (imagesResp.ok) {
        const imgs: ImageInfo[] = await imagesResp.json();
        const filtered = imgs.filter((img) => img.repository.includes(REPO_FILTER));
        console.log('[app] Loaded images: %d total, %d after filter', imgs.length, filtered.length);
        setImages(filtered);
        checkReleaseStatuses(filtered);
      } else {
        console.error('[app] Failed to fetch images:', imagesResp.status);
      }

      if (deploymentsResp.ok) {
        const deps: DeploymentInfo[] = await deploymentsResp.json();
        console.log('[app] Loaded deployments:', deps.length);
        setDeployments(deps);
      } else {
        console.error('[app] Failed to fetch deployments:', deploymentsResp.status);
      }
    } catch (err) {
      console.error('[app] Data fetch error:', err);
      addAlert(`Failed to load data: ${err}`, AlertVariant.danger);
    } finally {
      setLoadingData(false);
    }
  }, [token, user, addAlert]);

  const checkReleaseStatuses = useCallback((imgs: ImageInfo[]) => {
    if (!token) return;
    for (const img of imgs) {
      const uniqueDigests = [...new Set(img.tags.map((t) => t.manifest_digest))];
      if (uniqueDigests.length === 0) continue;

      setReleaseStatuses((prev) => {
        const next = { ...prev };
        for (const d of uniqueDigests) {
          if (!next[d]) {
            next[d] = { status: 'checking' };
          }
        }
        return next;
      });

      const quayHost = import.meta.env.VITE_QUAY_URL || '';
      const imageRef = quayHost
        ? `${quayHost.replace(/^https?:\/\//, '')}/${img.namespace}/${img.repository}`
        : `${img.namespace}/${img.repository}`;

      console.log('[app] Checking release status for', imageRef, uniqueDigests.length, 'digests');
      fetch('/api/check-release-status', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ imageRef, digests: uniqueDigests }),
      }).catch((err) => console.error('[app] Release status check failed:', err));
    }
  }, [token]);

  useEffect(() => {
    if (authenticated && token) {
      fetchData();
    }
  }, [authenticated, token, fetchData]);

  const { connected } = useWebSocket(user?.preferred_username ?? null, {
    images_update: (msg) => {
      console.log('[app] WebSocket images_update:', msg.data);
      const data = msg.data as { tenant: string; repository: string; namespace: string; tags: Tag[] };
      if (user && data.tenant === user.preferred_username && data.repository.includes(REPO_FILTER)) {
        setImages((prev) => {
          const idx = prev.findIndex(
            (img) => img.repository === data.repository && img.namespace === data.namespace
          );
          const updated = {
            repository: data.repository,
            namespace: data.namespace,
            tags: data.tags,
          };
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = updated;
            return next;
          }
          return [...prev, updated];
        });
        addAlert(`Images updated for ${data.namespace}/${data.repository}`, AlertVariant.info);
      }
    },
    deployment_update: (msg) => {
      console.log('[app] WebSocket deployment_update:', msg.data);
      const data = msg.data as { tenant: string; deployment: DeploymentInfo };
      if (user && data.tenant === user.preferred_username) {
        setDeployments((prev) => {
          const idx = prev.findIndex((d) => d.name === data.deployment.name);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = data.deployment;
            return next;
          }
          return [...prev, data.deployment];
        });
        addAlert(`Deployment updated: ${data.deployment.name}`, AlertVariant.info);
      }
    },
    attestation_created: (msg) => {
      console.log('[app] WebSocket attestation_created:', msg.data);
      const data = msg.data as { tenant: string; tlogIndex: string; approved: boolean; digest: string };
      if (user && data.tenant === user.preferred_username) {
        const action = data.approved ? 'approved' : 'rejected';
        addAlert(
          `Release ${action} successfully.`,
          AlertVariant.success
        );
        checkReleaseStatuses(images);
      }
    },
    release_status: (msg) => {
      const data = msg.data as { tenant: string; digest: string; status: string; approver: string; date: string; reason: string; docsFilename: string; docsBase64: string; error: string };
      if (user && data.tenant === user.preferred_username) {
        console.log('[app] Release status for %s: %s', data.digest.slice(0, 16), data.status);
        setReleaseStatuses((prev) => ({
          ...prev,
          [data.digest]: {
            status: data.status as ReleaseStatus['status'],
            approver: data.approver,
            date: data.date,
            reason: data.reason,
            docsFilename: data.docsFilename,
            docsBase64: data.docsBase64,
            error: data.error,
          },
        }));
      }
    },
  });

  const handleApprove = (deployment: DeploymentInfo) => {
    console.log('[app] Approve clicked for:', deployment.name);
    setModalDeployment(deployment);
    setModalIsApproval(true);
    setModalOpen(true);
  };

  const handleReject = (deployment: DeploymentInfo) => {
    console.log('[app] Reject clicked for:', deployment.name);
    setModalDeployment(deployment);
    setModalIsApproval(false);
    setModalOpen(true);
  };

  const handleAttestResult = (result: AttestResult) => {
    console.log('[app] Attest result:', result);
    if (result.success) {
      addAlert(
        `Attestation successful! Transparency log index: ${result.tlogIndex}`,
        AlertVariant.success
      );
    }
  };

  if (authLoading) {
    return (
      <Bullseye style={{ height: '100vh' }}>
        <div style={{ textAlign: 'center' }}>
          <Spinner size="xl" />
          <p style={{ marginTop: '1rem' }}>Authenticating with Keycloak...</p>
        </div>
      </Bullseye>
    );
  }

  if (authError) {
    return (
      <Bullseye style={{ height: '100vh' }}>
        <Alert variant="danger" title="Authentication Error">
          {authError}
        </Alert>
      </Bullseye>
    );
  }

  if (!authenticated || !user) {
    return (
      <Bullseye style={{ height: '100vh' }}>
        <Alert variant="warning" title="Not Authenticated">
          Please log in to continue.
        </Alert>
      </Bullseye>
    );
  }

  const appDeployments = deployments.filter(
    (d) => d.name !== 'parasol-db'
  );

  return (
    <Page
      masthead={
        <Masthead>
          <MastheadMain>
            <MastheadBrand>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style={{ width: '1.6rem', height: '1.6rem', fill: 'currentColor' }}>
                  <path d="M12 2C6.48 2 2 6.48 2 12h4c0-1.1.9-2 2-2s2 .9 2 2h4c0-1.1.9-2 2-2s2 .9 2 2h4c0-5.52-4.48-10-10-10z"/>
                  <path d="M13 12v7c0 1.1-.9 2-2 2s-2-.9-2-2v-1h2v1h0v-7h2z"/>
                </svg>
                <Title headingLevel="h1" size="lg">
                  <span style={{ opacity: 0.7 }}>Parasol</span><sup style={{ fontSize: '0.5em', opacity: 0.5 }}>&trade;</sup>{' '}Release Approval
                </Title>
              </span>
            </MastheadBrand>
          </MastheadMain>
          <MastheadContent>
            <Toolbar isFullHeight>
              <ToolbarContent>
                <ToolbarItem>
                  <Label color={connected ? 'green' : 'red'}>
                    {connected ? 'Live' : 'Disconnected'}
                  </Label>
                </ToolbarItem>
                <ToolbarItem>
                  {user.preferred_username} ({user.email})
                </ToolbarItem>
                <ToolbarGroup align={{ default: 'alignEnd' }}>
                  <ToolbarItem>
                    <Button
                      variant="plain"
                      onClick={() => setDarkMode((prev) => !prev)}
                      aria-label="Toggle theme"
                    >
                      {darkMode ? <SunIcon /> : <MoonIcon />}
                    </Button>
                  </ToolbarItem>
                  <ToolbarItem>
                    <Button variant="secondary" onClick={logout}>
                      Logout
                    </Button>
                  </ToolbarItem>
                </ToolbarGroup>
              </ToolbarContent>
            </Toolbar>
          </MastheadContent>
        </Masthead>
      }
    >
      <AlertGroup isToast isLiveRegion>
        {alerts.map((alert) => (
          <Alert
            key={alert.key}
            variant={alert.variant}
            title={alert.title}
            timeout={15000}
            onTimeout={() =>
              setAlerts((prev) => prev.filter((a) => a.key !== alert.key))
            }
          />
        ))}
      </AlertGroup>

      {inspectView ? (
        <AttestationInspect
          namespace={inspectView.namespace}
          repository={inspectView.repository}
          tag={inspectView.tag}
          digest={inspectView.digest}
          token={token!}
          onBack={() => setInspectView(null)}
        />
      ) : (
        <>
          <PageSection>
            {loadingData ? (
              <Bullseye>
                <Spinner size="xl" />
              </Bullseye>
            ) : (
              <>
                {images.length === 0 ? (
                  <Card style={{ marginBottom: '1rem' }}>
                    <CardTitle>Images</CardTitle>
                    <CardBody>No images found.</CardBody>
                  </Card>
                ) : images.map((img) => (
                  <div key={`${img.namespace}/${img.repository}`} style={{ marginBottom: '1rem' }}>
                    <ImageTable
                      tags={img.tags}
                      repository={img.repository}
                      namespace={img.namespace}
                      quayURL={quayURL}
                      deployments={deployments}
                      releaseStatuses={releaseStatuses}
                      onInspect={(ns, repo, tag, digest) =>
                        setInspectView({ namespace: ns, repository: repo, tag, digest })
                      }
                    />
                  </div>
                ))}

                {appDeployments.length > 0 ? (
                  appDeployments.map((dep) => (
                    <div key={dep.name} style={{ marginBottom: '1rem' }}>
                      <DeploymentCard
                        deployment={dep}
                        onApprove={handleApprove}
                        onReject={handleReject}
                      />
                    </div>
                  ))
                ) : (
                  <EmptyState>
                    <EmptyStateBody>
                      No application deployments found in{' '}
                      {user.preferred_username}-preprod namespace.
                    </EmptyStateBody>
                  </EmptyState>
                )}
              </>
            )}
          </PageSection>

          <ApprovalModal
            isOpen={modalOpen}
            deployment={modalDeployment}
            isApproval={modalIsApproval}
            token={token}
            idToken={idToken}
            tags={images.flatMap((img) => img.tags)}
            onClose={() => setModalOpen(false)}
            onResult={handleAttestResult}
          />
        </>
      )}
    </Page>
  );
};

export default App;
