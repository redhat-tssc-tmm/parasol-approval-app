import React from 'react';
import {
  Card,
  CardBody,
  CardTitle,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  Flex,
  FlexItem,
  Label,
  Split,
  SplitItem,
} from '@patternfly/react-core';
import { CheckCircleIcon, TimesCircleIcon } from '@patternfly/react-icons';
import { DeploymentInfo } from '../types';

interface DeploymentCardProps {
  deployment: DeploymentInfo;
  onApprove: (deployment: DeploymentInfo) => void;
  onReject: (deployment: DeploymentInfo) => void;
}

function shortenDigest(digest: string): string {
  if (!digest) return '-';
  if (digest.startsWith('sha256:')) {
    return `sha256:${digest.slice(7, 19)}...`;
  }
  return digest.slice(0, 16) + '...';
}

export const DeploymentCard: React.FC<DeploymentCardProps> = ({
  deployment,
  onApprove,
  onReject,
}) => {
  return (
    <Card>
      <CardTitle>
        <Split hasGutter>
          <SplitItem isFilled>
            Current Pre-Production Deployment
          </SplitItem>
          <SplitItem>
            {deployment.ready ? (
              <Label color="green" icon={<CheckCircleIcon />}>
                Ready
              </Label>
            ) : (
              <Label color="red" icon={<TimesCircleIcon />}>
                Not Ready
              </Label>
            )}
          </SplitItem>
        </Split>
      </CardTitle>
      <CardBody>
        <DescriptionList isHorizontal>
          <DescriptionListGroup>
            <DescriptionListTerm>Deployment</DescriptionListTerm>
            <DescriptionListDescription>
              {deployment.name}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Namespace</DescriptionListTerm>
            <DescriptionListDescription>
              {deployment.namespace}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Image</DescriptionListTerm>
            <DescriptionListDescription>
              <code style={{ wordBreak: 'break-all' }}>{deployment.image}</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Tag</DescriptionListTerm>
            <DescriptionListDescription>
              {deployment.tag || '-'}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Digest</DescriptionListTerm>
            <DescriptionListDescription>
              <code>{shortenDigest(deployment.digest)}</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Replicas</DescriptionListTerm>
            <DescriptionListDescription>
              {deployment.available}/{deployment.replicas}
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>

        <Flex style={{ marginTop: '1rem' }}>
          <FlexItem>
            <Button
              icon={<CheckCircleIcon />}
              onClick={() => onApprove(deployment)}
              isDisabled={!deployment.ready}
              style={deployment.ready ? { backgroundColor: '#3e8635', color: 'white' } : undefined}
            >
              Approve
            </Button>
          </FlexItem>
          <FlexItem>
            <Button
              icon={<TimesCircleIcon />}
              onClick={() => onReject(deployment)}
              isDisabled={!deployment.ready}
              style={deployment.ready ? { backgroundColor: '#c9190b', color: 'white' } : undefined}
            >
              Reject
            </Button>
          </FlexItem>
        </Flex>
      </CardBody>
    </Card>
  );
};
