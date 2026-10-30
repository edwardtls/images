import { randomBytes } from 'node:crypto';
import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  createTemplateAction,
  scaffolderActionsExtensionPoint,
} from '@backstage/plugin-scaffolder-node';

const dnsName = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/;
const quantity = /^(?:[1-9][0-9]*(?:m|Ki|Mi|Gi|Ti)?|0)$/;
type StringMap = Record<string, string>;

export type NamespaceRequest = {
  name: string;
  owner: string;
  description?: string;
  labels?: StringMap;
  annotations?: StringMap;
  quota?: {
    requestsCpu?: string;
    requestsMemory?: string;
    limitsCpu?: string;
    limitsMemory?: string;
    requestsStorage?: string;
    persistentVolumeClaims?: number;
    pods?: number;
    services?: number;
    secrets?: number;
    configMaps?: number;
  };
  limits?: {
    defaultRequestCpu?: string;
    defaultRequestMemory?: string;
    defaultCpu?: string;
    defaultMemory?: string;
  };
};

export type DatabaseRequest = {
  namespace: string;
  name: string;
  owner: string;
  instances?: number;
  databaseName?: string;
  databaseOwner?: string;
  storageClass?: string;
  storageSize?: string;
  walStorageSize?: string;
  requestCpu?: string;
  requestMemory?: string;
  limitCpu?: string;
  limitMemory?: string;
  postgresqlParameters?: StringMap;
  enablePodMonitor?: boolean;
  antiAffinity?: 'preferred' | 'required';
  primaryUpdateStrategy?: 'unsupervised' | 'supervised';
};

type GeneratedChange = {
  applicationName: string;
  files: Array<{ path: string; content: string }>;
};

export function buildBranchName(
  kind: 'namespace' | 'database',
  resourceName: string,
  suffix: string,
): string {
  const fixedLength = `backstage/${kind}--${suffix}`.length;
  const available = Math.max(1, 63 - fixedLength);
  const resource = resourceName.slice(0, available).replace(/-+$/, '');
  return `backstage/${kind}-${resource}-${suffix}`;
}

function quoted(value: string): string {
  return JSON.stringify(value);
}

function assertDnsName(value: string, field: string): string {
  const normalized = value.toLowerCase();
  if (!dnsName.test(normalized)) {
    throw new Error(`${field} must be a valid lowercase Kubernetes DNS label`);
  }
  return normalized;
}

function assertQuantity(value: string, field: string): string {
  if (!quantity.test(value)) {
    throw new Error(`${field} is not a supported Kubernetes resource quantity`);
  }
  return value;
}

function count(
  value: number | undefined,
  fallback: number,
  field: string,
): string {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 10000) {
    throw new Error(`${field} must be an integer between 1 and 10000`);
  }
  return String(result);
}

function assertMetadataMap(
  values: StringMap | undefined,
  field: string,
): StringMap {
  const result: StringMap = {};
  for (const [key, value] of Object.entries(values ?? {})) {
    if (!key || key.length > 253 || key.includes('\n')) {
      throw new Error(`${field} contains an invalid key`);
    }
    if (typeof value !== 'string' || value.includes('\u0000')) {
      throw new Error(`${field}.${key} must be a string`);
    }
    result[key] = value;
  }
  return result;
}

function mapLines(values: StringMap, indentation: number): string {
  const spaces = ' '.repeat(indentation);
  return Object.entries(values)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${spaces}${quoted(key)}: ${quoted(value)}`)
    .join('\n');
}

function renderApplication(options: {
  name: string;
  path: string;
  destinationNamespace: string;
}): string {
  const repoUrl = process.env.FORGEJO_ARGO_REPO_URL;
  if (!repoUrl) throw new Error('FORGEJO_ARGO_REPO_URL is not configured');
  return `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${options.name}
  namespace: argo
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: ${repoUrl}
    targetRevision: main
    path: ${options.path}
  destination:
    server: https://kubernetes.default.svc
    namespace: ${options.destinationNamespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=false
      - ServerSideApply=true
`;
}

export function renderNamespace(request: NamespaceRequest): GeneratedChange {
  const name = assertDnsName(request.name, 'Namespace name');
  const owner = request.owner.trim();
  if (!owner || owner.length > 128) {
    throw new Error('Owner must contain between 1 and 128 characters');
  }
  const labels = {
    ...assertMetadataMap(request.labels, 'labels'),
    'app.kubernetes.io/managed-by': 'backstage',
    'd00s.org/owner': owner,
  };
  const annotations = assertMetadataMap(request.annotations, 'annotations');
  if (request.description) {
    annotations['d00s.org/description'] = request.description.slice(0, 512);
  }

  const quota = request.quota ?? {};
  const hard: StringMap = {
    'requests.cpu': assertQuantity(quota.requestsCpu ?? '2', 'requests.cpu'),
    'requests.memory': assertQuantity(
      quota.requestsMemory ?? '4Gi',
      'requests.memory',
    ),
    'limits.cpu': assertQuantity(quota.limitsCpu ?? '4', 'limits.cpu'),
    'limits.memory': assertQuantity(
      quota.limitsMemory ?? '8Gi',
      'limits.memory',
    ),
    'requests.storage': assertQuantity(
      quota.requestsStorage ?? '40Gi',
      'requests.storage',
    ),
    persistentvolumeclaims: count(
      quota.persistentVolumeClaims,
      10,
      'persistentVolumeClaims',
    ),
    pods: count(quota.pods, 30, 'pods'),
    services: count(quota.services, 20, 'services'),
    secrets: count(quota.secrets, 30, 'secrets'),
    configmaps: count(quota.configMaps, 30, 'configMaps'),
  };
  const limits = request.limits ?? {};
  const defaultRequestCpu = assertQuantity(
    limits.defaultRequestCpu ?? '50m',
    'default request CPU',
  );
  const defaultRequestMemory = assertQuantity(
    limits.defaultRequestMemory ?? '64Mi',
    'default request memory',
  );
  const defaultCpu = assertQuantity(
    limits.defaultCpu ?? '1',
    'default CPU limit',
  );
  const defaultMemory = assertQuantity(
    limits.defaultMemory ?? '1Gi',
    'default memory limit',
  );
  const annotationsBlock = Object.keys(annotations).length
    ? `\n  annotations:\n${mapLines(annotations, 4)}`
    : '';
  const content = `apiVersion: v1
kind: Namespace
metadata:
  name: ${name}
  labels:
${mapLines(labels, 4)}${annotationsBlock}
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: namespace-quota
  namespace: ${name}
spec:
  hard:
${mapLines(hard, 4)}
---
apiVersion: v1
kind: LimitRange
metadata:
  name: container-defaults
  namespace: ${name}
spec:
  limits:
    - type: Container
      defaultRequest:
        cpu: ${quoted(defaultRequestCpu)}
        memory: ${quoted(defaultRequestMemory)}
      default:
        cpu: ${quoted(defaultCpu)}
        memory: ${quoted(defaultMemory)}
`;
  return {
    applicationName: `namespace-${name}`,
    files: [
      { path: `resources/namespaces/${name}/manifests.yaml`, content },
      {
        path: `apps/namespace-${name}.yaml`,
        content: renderApplication({
          name: `namespace-${name}`,
          path: `resources/namespaces/${name}`,
          destinationNamespace: name,
        }),
      },
    ],
  };
}

export function renderDatabase(request: DatabaseRequest): GeneratedChange {
  const namespace = assertDnsName(request.namespace, 'Namespace');
  const name = assertDnsName(request.name, 'Cluster name');
  const owner = request.owner.trim();
  if (!owner || owner.length > 128) {
    throw new Error('Owner must contain between 1 and 128 characters');
  }
  const instances = request.instances ?? 2;
  if (![1, 2, 3, 5].includes(instances)) {
    throw new Error('Instances must be 1, 2, 3, or 5');
  }
  const storageClass = assertDnsName(
    request.storageClass ?? 'ceph-csi-rbd',
    'Storage class',
  );
  const storageSize = assertQuantity(
    request.storageSize ?? '5Gi',
    'Storage size',
  );
  const requestCpu = assertQuantity(request.requestCpu ?? '50m', 'CPU request');
  const requestMemory = assertQuantity(
    request.requestMemory ?? '128Mi',
    'Memory request',
  );
  const limitCpu = assertQuantity(request.limitCpu ?? '1', 'CPU limit');
  const limitMemory = assertQuantity(
    request.limitMemory ?? '1Gi',
    'Memory limit',
  );
  const databaseName = assertDnsName(
    request.databaseName || name,
    'Database name',
  );
  const databaseOwner = assertDnsName(
    request.databaseOwner || name,
    'Database owner',
  );
  const parameters = assertMetadataMap(
    request.postgresqlParameters,
    'PostgreSQL parameters',
  );
  const walStorage = request.walStorageSize
    ? `  walStorage:\n    size: ${quoted(
        assertQuantity(request.walStorageSize, 'WAL storage size'),
      )}\n    storageClass: ${storageClass}\n`
    : '';
  const postgresql = Object.keys(parameters).length
    ? `  postgresql:\n    parameters:\n${mapLines(parameters, 6)}\n`
    : '';
  const podMonitor =
    request.enablePodMonitor ?? true
      ? `---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/managed-by: backstage
    d00s.org/owner: ${quoted(owner)}
spec:
  selector:
    matchLabels:
      cnpg.io/cluster: ${name}
  podMetricsEndpoints:
    - port: metrics
`
      : '';
  const content = `apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/managed-by: backstage
    d00s.org/owner: ${quoted(owner)}
spec:
  instances: ${instances}
  enableSuperuserAccess: false
  primaryUpdateStrategy: ${request.primaryUpdateStrategy ?? 'unsupervised'}
  bootstrap:
    initdb:
      database: ${databaseName}
      owner: ${databaseOwner}
  storage:
    size: ${quoted(storageSize)}
    storageClass: ${storageClass}
${walStorage}  resources:
    requests:
      cpu: ${quoted(requestCpu)}
      memory: ${quoted(requestMemory)}
    limits:
      cpu: ${quoted(limitCpu)}
      memory: ${quoted(limitMemory)}
  affinity:
    podAntiAffinityType: ${request.antiAffinity ?? 'preferred'}
${postgresql}${podMonitor}`;
  return {
    applicationName: `database-${namespace}-${name}`,
    files: [
      {
        path: `resources/databases/${namespace}/${name}/manifests.yaml`,
        content,
      },
      {
        path: `apps/database-${namespace}-${name}.yaml`,
        content: renderApplication({
          name: `database-${namespace}-${name}`,
          path: `resources/databases/${namespace}/${name}`,
          destinationNamespace: namespace,
        }),
      },
    ],
  };
}

type ForgejoOptions = {
  apiUrl: string;
  owner: string;
  repo: string;
  branch: string;
  token: string;
};

function forgejoHeaders(token: string) {
  return {
    Accept: 'application/json',
    Authorization: `token ${token}`,
    'Content-Type': 'application/json',
  };
}

async function forgejoRequest<T>(
  options: ForgejoOptions,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${options.apiUrl}${path}`, {
    ...init,
    headers: { ...forgejoHeaders(options.token), ...init.headers },
  });
  if (!response.ok) {
    throw new Error(
      `Forgejo request failed (${
        response.status
      }) for ${path}: ${await response.text()}`,
    );
  }
  return (await response.json()) as T;
}

async function fileExists(
  options: ForgejoOptions,
  path: string,
  branch = options.branch,
): Promise<boolean> {
  const endpoint = `/repos/${encodeURIComponent(
    options.owner,
  )}/${encodeURIComponent(options.repo)}/contents/${path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}?ref=${encodeURIComponent(branch)}`;
  const response = await fetch(`${options.apiUrl}${endpoint}`, {
    headers: forgejoHeaders(options.token),
  });
  if (response.status === 404) return false;
  if (!response.ok) {
    throw new Error(`Forgejo lookup failed (${response.status}) for ${path}`);
  }
  return true;
}

async function createPullRequest(
  options: ForgejoOptions,
  generated: GeneratedChange,
  kind: 'namespace' | 'database',
  resourceName: string,
): Promise<{ url: string; branch: string }> {
  for (const file of generated.files) {
    if (await fileExists(options, file.path)) {
      throw new Error(
        `${file.path} already exists on ${options.branch}; Backstage only creates new resources`,
      );
    }
  }
  const suffix = randomBytes(4).toString('hex');
  const branch = buildBranchName(kind, resourceName, suffix);
  const repoPath = `/repos/${encodeURIComponent(
    options.owner,
  )}/${encodeURIComponent(options.repo)}`;
  await forgejoRequest(options, `${repoPath}/branches`, {
    method: 'POST',
    body: JSON.stringify({
      new_branch_name: branch,
      old_branch_name: options.branch,
    }),
  });
  try {
    for (const file of generated.files) {
      await forgejoRequest(
        options,
        `${repoPath}/contents/${file.path
          .split('/')
          .map(encodeURIComponent)
          .join('/')}`,
        {
          method: 'POST',
          body: JSON.stringify({
            branch,
            message: `Add ${kind} ${resourceName} via Backstage`,
            content: Buffer.from(file.content).toString('base64'),
          }),
        },
      );
    }
    const pull = await forgejoRequest<{ html_url: string }>(
      options,
      `${repoPath}/pulls`,
      {
        method: 'POST',
        body: JSON.stringify({
          base: options.branch,
          head: branch,
          title: `[Backstage] Add ${kind} ${resourceName}`,
          body: 'Generated by Backstage as a create-only GitOps change. Review and edit the manifests in this pull request before merging. After merge, Git is the only configuration source of truth.',
        }),
      },
    );
    return { url: pull.html_url, branch };
  } catch (error) {
    await fetch(
      `${options.apiUrl}${repoPath}/branches/${branch
        .split('/')
        .map(encodeURIComponent)
        .join('/')}`,
      { method: 'DELETE', headers: forgejoHeaders(options.token) },
    );
    throw error;
  }
}

function createFactoryProvisionAction() {
  return createTemplateAction({
    id: 'factory:provision',
    description:
      'Creates an editable namespace or CloudNativePG change on a new branch and opens a Forgejo pull request.',
    schema: {
      input: {
        kind: z => z.enum(['namespace', 'database']),
        name: z => z.string().min(2).max(63),
        namespace: z => z.string().min(2).max(63).optional(),
        owner: z => z.string().min(1).max(128),
        description: z => z.string().max(512).optional(),
        labels: z => z.record(z.string(), z.string()).optional(),
        annotations: z => z.record(z.string(), z.string()).optional(),
        quota: z => z.record(z.string(), z.any()).optional(),
        limits: z => z.record(z.string(), z.any()).optional(),
        instances: z => z.number().int().optional(),
        databaseName: z => z.string().min(1).max(63).optional(),
        databaseOwner: z => z.string().min(1).max(63).optional(),
        storageClass: z => z.string().min(1).max(63).optional(),
        storageSize: z => z.string().optional(),
        walStorageSize: z => z.string().optional(),
        requestCpu: z => z.string().optional(),
        requestMemory: z => z.string().optional(),
        limitCpu: z => z.string().optional(),
        limitMemory: z => z.string().optional(),
        postgresqlParameters: z => z.record(z.string(), z.string()).optional(),
        enablePodMonitor: z => z.boolean().optional(),
        antiAffinity: z => z.enum(['preferred', 'required']).optional(),
        primaryUpdateStrategy: z =>
          z.enum(['unsupervised', 'supervised']).optional(),
      },
      output: {
        repositoryUrl: z => z.string(),
        applicationName: z => z.string(),
        pullRequestUrl: z => z.string(),
        branchName: z => z.string(),
      },
    },
    async handler(ctx) {
      const apiUrl = process.env.FORGEJO_API_URL;
      const repoUrl = process.env.FORGEJO_REPO_URL;
      const token = process.env.FORGEJO_TOKEN;
      const repoOwner = process.env.FORGEJO_REPO_OWNER ?? 'factory';
      const repo = process.env.FORGEJO_REPO ?? 'dev';
      const baseBranch = process.env.FORGEJO_BRANCH ?? 'main';
      if (!apiUrl || !repoUrl || !token) {
        throw new Error('Factory GitOps integration is not configured');
      }
      if (!process.env.FORGEJO_ARGO_REPO_URL) {
        throw new Error('FORGEJO_ARGO_REPO_URL is not configured');
      }
      const options: ForgejoOptions = {
        apiUrl,
        owner: repoOwner,
        repo,
        branch: baseBranch,
        token,
      };
      let generated: GeneratedChange;
      let resourceName: string;
      if (ctx.input.kind === 'namespace') {
        generated = renderNamespace(ctx.input as NamespaceRequest);
        resourceName = assertDnsName(ctx.input.name, 'Namespace name');
      } else {
        if (!ctx.input.namespace) {
          throw new Error('A target namespace is required for a database');
        }
        const namespace = assertDnsName(ctx.input.namespace, 'Namespace');
        const namespaceExists =
          (await fileExists(
            options,
            `resources/namespaces/${namespace}/manifests.yaml`,
          )) ||
          (await fileExists(options, `resources/${namespace}/manifests.yaml`));
        if (!namespaceExists) {
          throw new Error(
            `Namespace ${namespace} is not managed by this repository; create and merge it first`,
          );
        }
        generated = renderDatabase(ctx.input as DatabaseRequest);
        resourceName = `${namespace}-${assertDnsName(
          ctx.input.name,
          'Cluster name',
        )}`;
      }
      ctx.logger.info(
        `Opening a create-only ${ctx.input.kind} pull request in ${repoOwner}/${repo}`,
      );
      const pull = await createPullRequest(
        options,
        generated,
        ctx.input.kind,
        resourceName,
      );
      ctx.output('repositoryUrl', repoUrl);
      ctx.output('applicationName', generated.applicationName);
      ctx.output('pullRequestUrl', pull.url);
      ctx.output('branchName', pull.branch);
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
