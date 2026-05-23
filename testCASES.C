//test case 0
// #include <stdio.h>
// #include <stdlib.h>
// #define MAX 100

// int graph[MAX][MAX];
// int disc[MAX];
// int low[MAX];
// int stack[MAX];
// int inStack[MAX];
// int top = -1;
// int timer = 0;

// /* Push device into stack */
// void push(int node) {

//     stack[++top] = node;

//     inStack[node] = 1;
// }

// /* Pop device from stack */
// int pop() {

//     int node = stack[top--];

//     inStack[node] = 0;

//     return node;
// }

// /* Tarjan DFS Function */
// void tarjanDFS(int u, int n) {

//     /* Assign discovery and low values */
//     disc[u] = low[u] = ++timer;

//     printf("\n[SCAN] Analyzing Device-%d\n", u);

//     push(u);

//     /* Traverse all connected devices */
//     for(int v = 0; v < n; v++) {

//         if(graph[u][v]) {

//             printf("[TRAFFIC] Device-%d --> Device-%d detected\n", u, v);

//             /* If device not visited */
//             if(disc[v] == -1) {

//                 tarjanDFS(v, n);

//                 if(low[v] < low[u])
//                     low[u] = low[v];
//             }

//             /* Back edge found */
//             else if(inStack[v]) {

//                 if(disc[v] < low[u])
//                     low[u] = disc[v];
//             }
//         }
//     }

//     /* SCC Found */
//     if(low[u] == disc[u]) {

//         int scc[MAX];
//         int count = 0;

//         printf("\n[INFO] Communication Cluster Identified:\n");

//         while(stack[top] != u) {

//             scc[count] = stack[top];

//             printf("Device-%d ", stack[top]);

//             inStack[stack[top]] = 0;

//             top--;

//             count++;
//         }

//         scc[count] = stack[top];

//         printf("Device-%d ", stack[top]);

//         inStack[stack[top]] = 0;

//         top--;

//         count++;

//         /* Threat Classification */

//         if(count >= 3) {

//             printf("\n[ALERT] BOTNET TRAFFIC DETECTED!\n");

//             printf("[RISK] Multiple devices forming cyclic communication.\n");

//             printf("[ACTION] Recommend immediate isolation.\n");
//         }

//         else {

//             printf("\n[NORMAL] Normal communication pattern detected.\n");
//         }

//         printf("--------------------------------------------------\n");
//     }
// }

// int main() {

//     int n = 8;

//     /* Initialize arrays */
//     for(int i = 0; i < MAX; i++) {

//         disc[i] = -1;

//         low[i] = -1;

//         inStack[i] = 0;
//     }

//     /*
//        Simulated Network Traffic

//        BOTNET CLUSTER:
//        0 → 1 → 2 → 0

//        NORMAL TRAFFIC:
//        3 → 4

//        ANOTHER BOTNET:
//        5 → 6 → 7 → 5
//     */

//     /* Botnet Cluster 1 */
//     graph[0][1] = 1;
//     graph[1][2] = 1;
//     graph[2][0] = 1;

//     /* Normal Traffic */
//     graph[3][4] = 1;

//     /* Botnet Cluster 2 */
//     graph[5][6] = 1;
//     graph[6][7] = 1;
//     graph[7][5] = 1;

//     printf("============================================\n");
//     printf(" CYBERSECURITY NETWORK TRAFFIC ANALYZER\n");
//     printf(" Tarjan SCC Based Threat Detection System\n");
//     printf("============================================\n");

//     /* Start analysis */
//     for(int i = 0; i < n; i++) {

//         if(disc[i] == -1)
//             tarjanDFS(i, n);
//     }

//     printf("\n[SCAN COMPLETE] Network analysis finished.\n");

//     return 0;
// }


//test case 1
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdbool.h>

// #define MAX_NODES 100
// #define IP_LEN 16

// // Structure to track IP to internal ID mapping
// typedef struct {
//     char ip[IP_LEN];
// } Node;

// // Graph and Tarjan variables packed globally/struct-style for simplicity
// Node nodes[MAX_NODES];
// int node_count = 0;
// bool adj_matrix[MAX_NODES][MAX_NODES]; // Adjacency matrix representation

// // Tarjan State Arrays
// int dfn[MAX_NODES];      // Discovery time (index)
// int low[MAX_NODES];      // Lowest reachable node index
// bool on_stack[MAX_NODES];
// int stack[MAX_NODES];
// int stack_top = -1;
// int timer = 0;
// int cluster_count = 0;

// // Helper to look up or insert an IP into our node tracker
// int get_or_create_node(const char* ip) {
//     for (int i = 0; i < node_count; i++) {
//         if (strcmp(nodes[i].ip, ip) == 0) {
//             return i;
//         }
//     }
//     if (node_count < MAX_NODES) {
//         strncpy(nodes[node_count].ip, ip, IP_LEN - 1);
//         nodes[node_count].ip[IP_LEN - 1] = '\0';
//         return node_count++;
//     }
//     return -1;
// }

// void add_communication(const char* src_ip, const char* dst_ip) {
//     int src_id = get_or_create_node(src_ip);
//     int dst_id = get_or_create_node(dst_ip);
    
//     if (src_id != -1 && dst_id != -1) {
//         adj_matrix[src_id][dst_id] = true;
//     }
// }

// // Minimal helper macros/logic
// int min(int a, int b) { return (a < b) ? a : b; }

// // Core Tarjan DFS Implementation
// void strong_connect(int u) {
//     dfn[u] = low[u] = ++timer;
//     stack[++stack_top] = u;
//     on_stack[u] = true;

//     for (int v = 0; v < node_count; v++) {
//         if (!adj_matrix[u][v]) continue; // No communication edge

//         if (!dfn[v]) { // Successor v has not yet been visited
//             strong_connect(v);
//             low[u] = min(low[u], low[v]);
//         } else if (on_stack[v]) { // Successor v is in the stack
//             low[u] = min(low[u], dfn[v]);
//         }
//     }

//     // If u is a root node, pop the stack and generate an SCC cluster
//     if (low[u] == dfn[u]) {
//         cluster_count++;
//         printf("\n[+] INFRASTRUCTURE CLUSTER #%d\n", cluster_count);
//         printf("    Affected IPs: ");
        
//         int v;
//         int current_cluster_size = 0;
//         // Temporary array to format output nicely
//         int cluster_nodes[MAX_NODES];

//         do {
//             v = stack[stack_top--];
//             on_stack[v] = false;
//             cluster_nodes[current_cluster_size++] = v;
//         } while (v != u);

//         for (int i = 0; i < current_cluster_size; i++) {
//             printf("%s%s", nodes[cluster_nodes[i]].ip, (i == current_cluster_size - 1) ? "" : ", ");
//         }
//         printf("\n    Size: %d nodes\n", current_cluster_size);

//         if (current_cluster_size > 1) {
//             printf("    STATUS: HIGH RISK - Cyclic C2 Communication Loop Detected.\n");
//             printf("    ACTION: Quarantine all nodes simultaneously to prevent fallback behaviors.\n");
//         } else {
//             printf("    STATUS: Low/Medium Risk - Isolated Node or Single Inbound/Outbound Pivot.\n");
//             printf("    ACTION: Monitor traffic logs for lateral movement.\n");
//         }
//     }
// }

// void run_tarjan_analysis() {
//     // Initialize state arrays
//     memset(dfn, 0, sizeof(dfn));
//     memset(low, 0, sizeof(low));
//     memset(on_stack, 0, sizeof(on_stack));
//     timer = 0;
//     cluster_count = 0;

//     printf("=================================================================\n");
//     printf(" THREAT INTEL NETWORKS: TARJAN'S INFRASTRUCTURE ANALYSIS (C-LANG)\n");
//     printf("=================================================================\n");
//     printf("Processing firewall logs and tracking communication links...\n");

//     for (int i = 0; i < node_count; i++) {
//         if (!dfn[i]) {
//             strong_connect(i);
//         }
//     }
    
//     printf("\n-----------------------------------------------------------------\n");
//     printf("Analysis Complete. Total Unique Assets: %d | Clusters Formed: %d\n", node_count, cluster_count);
//     printf("=================================================================\n");
// }

// int main() {
//     // Clear our communication matrix
//     memset(adj_matrix, 0, sizeof(adj_matrix));

//     // --- Simulation Scenario Data ---
    
//     // Cluster A: Core Botnet infrastructure communicating in a closed circle
//     add_communication("192.168.1.10", "192.168.1.11");
//     add_communication("192.168.1.11", "192.168.1.12");
//     add_communication("192.168.1.12", "192.168.1.10");

//     // Cluster B: Secondary Malicious Relay Loop 
//     add_communication("10.0.0.5", "10.0.0.6");
//     add_communication("10.0.0.6", "10.0.0.5");

//     // One-way pivot link from the core botnet (1.11) reaching out to the relays (0.5)
//     add_communication("192.168.1.11", "10.0.0.5");

//     // Cluster C: An isolated compromised victim server exfiltrating to the botnet master
//     add_communication("172.16.5.20", "192.168.1.10");

//     // Run the analysis
//     run_tarjan_analysis();

//     return 0;
// }


// test case 2
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdbool.h>

// #define MAX_NODES 100
// #define IP_LEN 16

// typedef struct {
//     char ip[IP_LEN];
// } Node;

// // Structure to capture cluster metadata for sorted reporting
// typedef struct {
//     int id;
//     int size;
//     char ips_list[512];
//     char risk_status[16];
//     char action_plan[128];
// } SecurityCluster;

// Node nodes[MAX_NODES];
// int node_count = 0;
// int edge_count = 0;
// bool adj_matrix[MAX_NODES][MAX_NODES];

// // Tarjan State
// int dfn[MAX_NODES];
// int low[MAX_NODES];
// bool on_stack[MAX_NODES];
// int stack[MAX_NODES];
// int stack_top = -1;
// int timer = 0;

// // Tracking arrays for reporting
// SecurityCluster clusters[MAX_NODES];
// int cluster_count = 0;

// int get_or_create_node(const char* ip) {
//     for (int i = 0; i < node_count; i++) {
//         if (strcmp(nodes[i].ip, ip) == 0) return i;
//     }
//     if (node_count < MAX_NODES) {
//         strncpy(nodes[node_count].ip, ip, IP_LEN - 1);
//         nodes[node_count].ip[IP_LEN - 1] = '\0';
//         return node_count++;
//     }
//     return -1;
// }

// void add_communication(const char* src_ip, const char* dst_ip) {
//     int src_id = get_or_create_node(src_ip);
//     int dst_id = get_or_create_node(dst_ip);
//     if (src_id != -1 && dst_id != -1) {
//         if (!adj_matrix[src_id][dst_id]) {
//             adj_matrix[src_id][dst_id] = true;
//             edge_count++;
//         }
//     }
// }

// int min(int a, int b) { return (a < b) ? a : b; }

// // Comparator function to sort clusters from smallest size to largest size
// int compare_clusters(const void* a, const void* b) {
//     return ((SecurityCluster*)a)->size - ((SecurityCluster*)b)->size;
// }

// void strong_connect(int u) {
//     dfn[u] = low[u] = ++timer;
//     stack[++stack_top] = u;
//     on_stack[u] = true;

//     for (int v = 0; v < node_count; v++) {
//         if (!adj_matrix[u][v]) continue;

//         if (!dfn[v]) {
//             strong_connect(v);
//             low[u] = min(low[u], low[v]);
//         } else if (on_stack[v]) {
//             low[u] = min(low[u], dfn[v]);
//         }
//     }

//     if (low[u] == dfn[u]) {
//         SecurityCluster current_cluster;
//         current_cluster.id = cluster_count + 1;
//         current_cluster.size = 0;
//         current_cluster.ips_list[0] = '\0';

//         int v;
//         do {
//             v = stack[stack_top--];
//             on_stack[v] = false;
            
//             strcat(current_cluster.ips_list, nodes[v].ip);
//             current_cluster.size++;
            
//             // Peek at next element to see if we append comma
//             if (stack_top >= 0 && on_stack[stack[stack_top]] && low[stack[stack_top]] == low[u]) {
//                 // Logic flag handling to check if it belongs to same loop iteration
//             }
//             strcat(current_cluster.ips_list, " "); // Using space delimited for simple rendering
//         } while (v != u);

//         // Assign Three-Tiered Risk Profiles
//         if (current_cluster.size == 1) {
//             strcpy(current_cluster.risk_status, "NORMAL");
//             strcpy(current_cluster.action_plan, "Routine monitoring. Log asset behavior anomalies.");
//         } else if (current_cluster.size > 1 && current_cluster.size <= 3) {
//             strcpy(current_cluster.risk_status, "MEDIUM RISK");
//             strcpy(current_cluster.action_plan, "Isolate endpoints. Investigate secondary pivot links.");
//         } else {
//             strcpy(current_cluster.risk_status, "HIGH RISK");
//             strcpy(current_cluster.action_plan, "CRITICAL: Widespread infrastructure loop. Quarantine all nodes instantly.");
//         }

//         clusters[cluster_count++] = current_cluster;
//     }
// }

// void run_tarjan_analysis() {
//     memset(dfn, 0, sizeof(dfn));
//     memset(low, 0, sizeof(low));
//     memset(on_stack, 0, sizeof(on_stack));
//     timer = 0;
//     cluster_count = 0;

//     for (int i = 0; i < node_count; i++) {
//         if (!dfn[i]) strong_connect(i);
//     }

//     // Sort findings from Minimum Nodes Affected to Maximum Nodes Affected
//     qsort(clusters, cluster_count, sizeof(SecurityCluster), compare_clusters);

//     // Terminal Screen Output
//     printf("=================================================================\n");
//     printf(" THREAT INTEL NETWORKS: TARJAN'S INFRASTRUCTURE ANALYSIS\n");
//     printf("=================================================================\n");
//     printf("[i] ALGORITHM COMPLEXITY:\n");
//     printf("    -> Time Complexity: O(V + E)\n");
//     printf("    -> Context: Evaluated %d Assets (V) and %d Links (E) in a single pass.\n", node_count, edge_count);
//     printf("-----------------------------------------------------------------\n");
//     printf("DETECTION REPORT (Ordered by threat scale / nodes affected):\n");

//     for (int i = 0; i < cluster_count; i++) {
//         printf("\n[+] CLUSTER LAYER #%d\n", i + 1);
//         printf("    Nodes Affected : %d\n", clusters[i].size);
//         printf("    Tracked Targets: %s\n", clusters[i].ips_list);
//         printf("    RISK RATING    : %s\n", clusters[i].risk_status);
//         printf("    ACTION PLAN    : %s\n", clusters[i].action_plan);
//     }
    
//     printf("\n=================================================================\n");
//     printf("Analysis Complete. Total Threat Clusters Categorized: %d\n", cluster_count);
//     printf("=================================================================\n");
// }

// int main() {
//     memset(adj_matrix, 0, sizeof(adj_matrix));

//     // NORMAL RISK DATA (Single node, no communication loops back to it)
//     add_communication("172.16.5.20", "192.168.1.10");

//     // MEDIUM RISK DATA (Loop of 2-3 nodes interacting)
//     add_communication("10.0.0.5", "10.0.0.6");
//     add_communication("10.0.0.6", "10.0.0.5");

//     // HIGH RISK DATA (Large infrastructure loop of 4 nodes)
//     add_communication("192.168.1.10", "192.168.1.11");
//     add_communication("192.168.1.11", "192.168.1.12");
//     add_communication("192.168.1.12", "192.168.1.13");
//     add_communication("192.168.1.13", "192.168.1.10");

//     run_tarjan_analysis();
//     return 0;
// }