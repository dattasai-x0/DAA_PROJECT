//test case 3
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#define MAX_NODES 150
#define IP_LEN 16

typedef struct {
    char ip[IP_LEN];
} Node;

typedef struct {
    int id;
    int size;
    char ips_list[1024];
    char risk_status[16];
    char action_plan[128];
} SecurityCluster;

Node nodes[MAX_NODES];
int node_count = 0;
int edge_count = 0;
bool adj_matrix[MAX_NODES][MAX_NODES];

// Tarjan Core Engine State
int dfn[MAX_NODES];
int low[MAX_NODES];
bool on_stack[MAX_NODES];
int stack[MAX_NODES];
int stack_top = -1;
int timer = 0;

SecurityCluster clusters[MAX_NODES];
int cluster_count = 0;

// Internal Registry Management
int get_or_create_node(const char* ip) {
    for (int i = 0; i < node_count; i++) {
        if (strcmp(nodes[i].ip, ip) == 0) return i;
    }
    if (node_count < MAX_NODES) {
        strncpy(nodes[node_count].ip, ip, IP_LEN - 1);
        nodes[node_count].ip[IP_LEN - 1] = '\0';
        return node_count++;
    }
    return -1;
}

void add_communication(const char* src_ip, const char* dst_ip) {
    int src_id = get_or_create_node(src_ip);
    int dst_id = get_or_create_node(dst_ip);
    if (src_id != -1 && dst_id != -1) {
        if (!adj_matrix[src_id][dst_id]) {
            adj_matrix[src_id][dst_id] = true;
            edge_count++;
        }
    }
}

// Utility IP Generator
void generate_random_ip(char* buffer, int network_type) {
    if (network_type == 0) {
        sprintf(buffer, "192.168.1.%d", rand() % 254 + 1);
    } else if (network_type == 1) {
        sprintf(buffer, "10.0.%d.%d", rand() % 5 + 1, rand() % 254 + 1);
    } else {
        sprintf(buffer, "172.16.5.%d", rand() % 254 + 1);
    }
}

/* 
   Dynamically generates natural network environments.
   Ensures representation across all three risk categories using topological loops.
*/
void seed_random_threat_landscape() {
    char ip_pool[30][IP_LEN];
    
    // Create pool of unique simulated network assets
    for (int i = 0; i < 30; i++) {
        generate_random_ip(ip_pool[i], i % 3);
    }

    // 1. Generate NORMAL Risk Profiles (Dispersed nodes pointing to a target, no cyclical loops)
    for (int i = 0; i < 4; i++) {
        add_communication(ip_pool[i], ip_pool[i + 4]); 
    }

    // 2. Generate MEDIUM RISK Loops (Small cycles of 2-3 endpoints)
    // Loop 1 (2 Nodes)
    add_communication(ip_pool[8], ip_pool[9]);
    add_communication(ip_pool[9], ip_pool[8]);
    
    // Loop 2 (3 Nodes)
    add_communication(ip_pool[10], ip_pool[11]);
    add_communication(ip_pool[11], ip_pool[12]);
    add_communication(ip_pool[12], ip_pool[10]);

    // 3. Generate HIGH RISK Loop (Large complex cycle of 4 to 8 nodes)
    int large_loop_size = 4 + (rand() % 4); // Evaluates between 4 and 7 nodes dynamically
    int start_idx = 15;
    for (int i = 0; i < large_loop_size; i++) {
        int current = start_idx + i;
        int next = start_idx + ((i + 1) % large_loop_size);
        add_communication(ip_pool[current], ip_pool[next]);
    }
    
    // Mix in random noise connections (Simulation of outbound egress pivoting)
    for (int i = 0; i < 5; i++) {
        int src = rand() % 30;
        int dst = rand() % 30;
        if (src != dst) {
            add_communication(ip_pool[src], ip_pool[dst]);
        }
    }
}

int min(int a, int b) { return (a < b) ? a : b; }

int compare_clusters(const void* a, const void* b) {
    return ((SecurityCluster*)a)->size - ((SecurityCluster*)b)->size;
}

void strong_connect(int u) {
    dfn[u] = low[u] = ++timer;
    stack[++stack_top] = u;
    on_stack[u] = true;

    for (int v = 0; v < node_count; v++) {
        if (!adj_matrix[u][v]) continue;

        if (!dfn[v]) {
            strong_connect(v);
            low[u] = min(low[u], low[v]);
        } else if (on_stack[v]) {
            low[u] = min(low[u], dfn[v]);
        }
    }

    if (low[u] == dfn[u]) {
        SecurityCluster current_cluster;
        current_cluster.id = cluster_count + 1;
        current_cluster.size = 0;
        current_cluster.ips_list[0] = '\0';

        int v;
        do {
            v = stack[stack_top--];
            on_stack[v] = false;
            
            strcat(current_cluster.ips_list, nodes[v].ip);
            strcat(current_cluster.ips_list, "  "); 
            current_cluster.size++;
        } while (v != u);

        // Classify based on your specifications
        if (current_cluster.size == 1) {
            strcpy(current_cluster.risk_status, "NORMAL");
            strcpy(current_cluster.action_plan, "Routine monitoring. Log asset behavior anomalies.");
        } else if (current_cluster.size > 1 && current_cluster.size <= 3) {
            strcpy(current_cluster.risk_status, "MEDIUM RISK");
            strcpy(current_cluster.action_plan, "Isolate endpoints. Investigate secondary pivot links.");
        } else {
            strcpy(current_cluster.risk_status, "HIGH RISK");
            strcpy(current_cluster.action_plan, "CRITICAL: Widespread infrastructure loop. Quarantine all nodes instantly.");
        }

        clusters[cluster_count++] = current_cluster;
    }
}

void run_tarjan_analysis() {
    memset(dfn, 0, sizeof(dfn));
    memset(low, 0, sizeof(low));
    memset(on_stack, 0, sizeof(on_stack));
    timer = 0;
    cluster_count = 0;

    for (int i = 0; i < node_count; i++) {
        if (!dfn[i]) strong_connect(i);
    }

    // Ascending sort based on nodes count size
    qsort(clusters, cluster_count, sizeof(SecurityCluster), compare_clusters);

    printf("=================================================================\n");
    printf(" THREAT INTEL NETWORKS: DYNAMIC TARJAN SEC-LOG ANALYSIS\n");
    printf("=================================================================\n");
    printf("[i] ALGORITHM COMPLEXITY:\n");
    printf("    -> Time Complexity: O(V + E)\n");
    printf("    -> Space Complexity: O(V^2) (Adjacency Matrix Configuration)\n");
    printf("    -> Context: Evaluated %d Assets (V) with %d Communications (E)\n", node_count, edge_count);
    printf("-----------------------------------------------------------------\n");
    printf("DETECTION REPORT (Sorted Monotonically by Cluster Scale):\n");

    for (int i = 0; i < cluster_count; i++) {
        printf("\n[+] DETECTED ZONE CONTAINER #%d\n", i + 1);
        printf("    Nodes Affected : %d\n", clusters[i].size);
        printf("    Tracked Targets: %s\n", clusters[i].ips_list);
        printf("    RISK RATING    : %s\n", clusters[i].risk_status);
        printf("    ACTION PLAN    : %s\n", clusters[i].action_plan);
    }
    
    printf("\n=================================================================\n");
    printf("Analysis Run Finished. Total Isolated Containers Uncovered: %d\n", cluster_count);
    printf("=================================================================\n");
}

int main() {
    srand((unsigned int)time(NULL));
    memset(adj_matrix, 0, sizeof(adj_matrix));

    // Dynamic topology engine generation call
    seed_random_threat_landscape();

    run_tarjan_analysis();
    return 0;
}