import { renderDatabase, renderNamespace } from './factoryProvisioner';

describe('factory manifest rendering', () => {
  beforeEach(() => {
    process.env.FORGEJO_ARGO_REPO_URL =
      'ssh://git@192.168.61.210/factory/dev.git';
  });

  it('renders an editable namespace without hidden request state', () => {
    const change = renderNamespace({
      name: 'handoff-ns-test',
      owner: 'engineering',
      description: 'isolated integration test',
      labels: { 'cost-center': 'test' },
      quota: { requestsMemory: '2Gi', pods: 12 },
    });
    expect(change.applicationName).toBe('namespace-handoff-ns-test');
    expect(change.files.map(file => file.path)).toEqual([
      'resources/namespaces/handoff-ns-test/manifests.yaml',
      'apps/namespace-handoff-ns-test.yaml',
    ]);
    expect(change.files[0].content).toContain('"requests.memory": "2Gi"');
    expect(change.files[0].content).toContain('"pods": "12"');
    expect(change.files[0].content).not.toContain('kind: Cluster');
  });

  it('renders a CNPG cluster into an existing namespace only', () => {
    const change = renderDatabase({
      namespace: 'handoff-ns-test',
      name: 'orders-db',
      owner: 'engineering',
      instances: 3,
      storageSize: '10Gi',
      walStorageSize: '2Gi',
      postgresqlParameters: { max_connections: '80' },
    });
    expect(change.applicationName).toBe('database-handoff-ns-test-orders-db');
    expect(change.files[0].path).toBe(
      'resources/databases/handoff-ns-test/orders-db/manifests.yaml',
    );
    expect(change.files[0].content).toContain('instances: 3');
    expect(change.files[0].content).toContain('"max_connections": "80"');
    expect(change.files[0].content).not.toContain('kind: Namespace');
  });

  it('rejects unsafe names and quantities', () => {
    expect(() =>
      renderNamespace({ name: '../escape', owner: 'engineering' }),
    ).toThrow(/DNS label/);
    expect(() =>
      renderDatabase({
        namespace: 'handoff-ns-test',
        name: 'orders-db',
        owner: 'engineering',
        storageSize: '5Gi\nkind: Secret',
      }),
    ).toThrow(/quantity/);
  });
});
