export interface Tag {
  name: string;
  manifest_digest: string;
  last_modified: string;
  size: number;
}

export interface ImageInfo {
  repository: string;
  namespace: string;
  tags: Tag[];
}

export interface DeploymentInfo {
  name: string;
  namespace: string;
  image: string;
  tag: string;
  digest: string;
  ready: boolean;
  replicas: number;
  available: number;
}

export interface AttestResult {
  success: boolean;
  tlogIndex: string;
  message: string;
  stdout: string;
  stderr: string;
}

export interface ReleaseStatus {
  status: 'approved' | 'rejected' | 'none' | 'error' | 'checking';
  approver?: string;
  date?: string;
  reason?: string;
  docsFilename?: string;
  docsBase64?: string;
  error?: string;
}

export interface WSMessage {
  type: 'images_update' | 'deployment_update' | 'attestation_created' | 'release_status';
  data: Record<string, unknown>;
}

export interface UserProfile {
  preferred_username: string;
  email: string;
  given_name: string;
  family_name: string;
  sub: string;
}
