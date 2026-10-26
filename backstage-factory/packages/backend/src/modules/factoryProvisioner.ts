import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';

const dnsName = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/;

function yamlString(value: string): string {
  return JSON.stringify(value);
}

async function putForgejoFile(options: {
  apiUrl: string;
  owner: string;
  repo: string;
  branch: string;
  token: string;
  path: string;
  content: string;
  message: string;
}) {
  const endpoint = `${options.apiUrl}/repos/${encodeURIComponent(options.owner)}/${encodeURIComponent(options.repo)}/contents/${options.path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`;
  const headers = {
    Accept: 'application/json',
    Authorization: `token ${options.token}`,
    'Content-Type': 'application/json',
  };
  const current = await fetch(`${endpoint}?ref=${encodeURIComponent(options.branch)}`, {
    headers,
  });
  let sha: string | undefined;
  if (current.ok) {
    const body = (await current.json()) as { sha?: string };
    sha = body.sha;
  } else if (current.status !== 404) {
    throw new Error(`Forgejo lookup failed (${current.status})`);
  }

  const response = await fetch(endpoint, {
    method: 'PUT',
    headers,
    body: JSON.stringify({
      branch: options.branch,
      message: options.message,
      content: Buffer.from(options.content).toString('base64'),
      ...(sha ? { sha } : {}),
    }),
  });
  if (!response.ok) {
    throw new Error(
      `Forgejo write failed for ${options.path} (${response.status}): ${await response.text()}`,
    );
  }
}

function namespaceManifest(name: string, owner: string): string {
  return `apiVersion: v1
kind: Namespace
metadata:
  name: ${name}
  labels:
    app.kubernetes.io/managed-by: backstage
    d00s.org/owner: ${yamlString(owner)}
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-defaults
  namespace: ${name}
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "4"
    limits.memory: 8Gi
    persistentvolumeclaims: "10"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: team-defaults
  namespace: ${name}
spec:
  limits:
    - type: Container
      defaultRequest:
        cpu: 50m
        memory: 64Mi
      default:
        cpu: "1"
        memory: 1Gi
`;
}

function databaseManifest(
  name: string,
  owner: string,
  instances: number,
  storageSize: string,
): string {
  return `${namespaceManifest(name, owner)}---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: ${name}
  namespace: ${name}
  labels:
    app.kubernetes.io/managed-by: backstage
    d00s.org/owner: ${yamlString(owner)}
spec:
  instances: ${instances}
  storage:
    size: ${storageSize}
    storageClass: ceph-csi-rbd
  resources:
    requests:
      cpu: 50m
      memory: 128Mi
    limits:
      cpu: "1"
      memory: 1Gi
  monitoring:
    enablePodMonitor: true
`;
}

function applicationManifest(name: string, repoUrl: string): string {
  return `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: team-${name}
  namespace: argo
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: ${repoUrl}
    targetRevision: main
    path: resources/${name}
  destination:
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - ServerSideApply=true
`;
}

function createFactoryProvisionAction() {
  return createTemplateAction({
    id: 'factory:provision',
    description:
      'Commits a constrained namespace or CloudNativePG database definition to the cluster GitOps repository.',
    schema: {
      input: {
        kind: z => z.enum(['namespace', 'database']),
        name: z => z.string().min(2).max(63),
        owner: z => z.string().min(1).max(128),
        instances: z => z.number().int().min(1).max(3).optional(),
        storageSize: z =>
          z.string().regex(/^[1-9][0-9]*(?:Gi|Ti)$/).optional(),
      },
      output: {
        repositoryUrl: z => z.string(),
        applicationName: z => z.string(),
      },
    },
    async handler(ctx) {
      const name = ctx.input.name.toLowerCase();
      if (!dnsName.test(name)) {
        throw new Error('Name must be a valid lowercase Kubernetes DNS label');
      }

      const apiUrl = process.env.FORGEJO_API_URL;
      const repoUrl = process.env.FORGEJO_REPO_URL;
      const token = process.env.FORGEJO_TOKEN;
      const repoOwner = process.env.FORGEJO_REPO_OWNER ?? 'factory';
      const repo = process.env.FORGEJO_REPO ?? 'dev';
      const branch = process.env.FORGEJO_BRANCH ?? 'main';
      if (!apiUrl || !repoUrl || !token) {
        throw new Error('Factory GitOps integration is not configured');
      }
      const argoRepoUrl = process.env.FORGEJO_ARGO_REPO_URL ?? repoUrl;

      const content =
        ctx.input.kind === 'database'
          ? databaseManifest(
              name,
              ctx.input.owner,
              ctx.input.instances ?? 2,
              ctx.input.storageSize ?? '5Gi',
            )
          : namespaceManifest(name, ctx.input.owner);

      ctx.logger.info(`Committing ${ctx.input.kind} ${name} to ${repoOwner}/${repo}`);
      await putForgejoFile({
        apiUrl,
        owner: repoOwner,
        repo,
        branch,
        token,
        path: `resources/${name}/manifests.yaml`,
        content,
        message: `Provision ${ctx.input.kind} ${name} via Backstage`,
      });
      await putForgejoFile({
        apiUrl,
        owner: repoOwner,
        repo,
        branch,
        token,
        path: `apps/team-${name}.yaml`,
        content: applicationManifest(name, argoRepoUrl),
        message: `Register ${ctx.input.kind} ${name} with Argo CD`,
      });

      ctx.output('repositoryUrl', repoUrl);
      ctx.output('applicationName', `team-${name}`);
    },
  });
}

export default createBackendModule({
  pluginId: 'scaffolder',
  moduleId: 'factory-provisioner',
  register(reg) {
    reg.registerInit({
      deps: { scaffolder: scaffolderActionsExtensionPoint },
      async init({ scaffolder }) {
        scaffolder.addActions(createFactoryProvisionAction());
      },
    });
  },
});
