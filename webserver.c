//
// Created by khim on 11/7/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/select.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_SIZE 100
#define MAX_REPLIES 10

const char *MY_PORT = {0};

typedef struct {
    int node_id;
    const char* node_ip;
    const char* node_port;
    int node_port_int;
    int pred_id;
    const char* pred_ip;
    int pred_port;
    int succ_id;
    const char* succ_ip;
    int succ_port;
} NodeInfo;

typedef struct {
    uint8_t message_type;
    uint16_t hash_id;
    uint16_t node_id;
    char node_ip[INET_ADDRSTRLEN];
    uint16_t node_port;
} UDP_Packet;

// uint16_t last_hash = 3; // TODO das muss ordentlich werden https://isis.tu-berlin.de/mod/forum/discuss.php?d=633206
size_t r = 0;
UDP_Packet REPLIES[MAX_REPLIES] = {0};

UDP_Packet *search_reply(uint16_t hash_id) {
    printf("%s: ...searching\n", MY_PORT);
    for (size_t i = 0; i < MAX_REPLIES; i++) {
        // REPLIES[i].hash_id := pred_id
        bool yes = REPLIES[i].hash_id <= REPLIES[i].node_id ?
            hash_id <= REPLIES[i].node_id && hash_id > REPLIES[i].hash_id :
            hash_id <= REPLIES[i].node_id || hash_id > REPLIES[i].hash_id;
        if (yes) {
            return &REPLIES[i];
        }
    }
    return NULL;
}

void put_reply(const UDP_Packet packet) {
    REPLIES[r] = packet;
    r = (r + 1) % MAX_REPLIES;
}

NodeInfo init_node_info(const uint16_t node_id, const char *node_port, const char *node_ip) {
    NodeInfo node_info;

    node_info.node_id = node_id;
    node_info.node_ip = node_ip;
    node_info.node_port = node_port;
    node_info.node_port_int = atoi(node_port);

    const char *pred_id = getenv("PRED_ID");
    node_info.pred_id = pred_id ? atoi(pred_id) : 0;

    const char *pred_ip = getenv("PRED_IP");
    node_info.pred_ip = pred_ip ? pred_ip : "0.0.0.0";

    const char *pred_port = getenv("PRED_PORT");
    node_info.pred_port = pred_port ? atoi(pred_port) : 0;

    const char *succ_id = getenv("SUCC_ID");
    node_info.succ_id = succ_id ? atoi(succ_id) : 0;

    const char *succ_ip = getenv("SUCC_IP");
    node_info.succ_ip = succ_ip ? succ_ip : "0.0.0.0";

    const char *succ_port = getenv("SUCC_PORT");
    node_info.succ_port = succ_port ? atoi(succ_port) : 0;

    return node_info;
}

int parse_key_value(const char *line, char *key, char *value) {
    const char *delimiter_pos = strchr(line, ':');
    if (delimiter_pos == NULL) {
        return 0;
    }

    size_t key_length = delimiter_pos - line;
    if (key_length == 0) {
        return 0;
    }
    strncpy(key, line, key_length);
    key[key_length] = '\0';

    const char *value_start = delimiter_pos + 1;
    while (*value_start == ' ') {
        value_start++;
    }
    strcpy(value, value_start);

    return 1;
}

typedef struct {
    int result;       // -1 = ungültig, 0 = GET, 1 = PUT, 2 = DELETE, 3 sonst
    char uri[1024];
    int content_length;
} ValidationResult;

/**
 * @param str *
 * @return -1 wenn ungültig. 0 Wenn GET. 1 PUT. 2 DELETE. 3 sonst
 */
ValidationResult validate(const char *str) {
    ValidationResult validation = {.result = -1, .uri = "", .content_length = -1};

    if (str == NULL) {
        return validation;
    }

    char temp[8192];
    strncpy(temp, str, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *line = strtok(temp, "\r\n");
    if (line == NULL) {
        return validation;
    }

    const char *DELIMITER = " ";
    char *method = strtok(line, DELIMITER);
    char *uri = strtok(NULL, DELIMITER);
    char *http_version = strtok(NULL, DELIMITER);

    if (method == NULL || uri == NULL || http_version == NULL ||
            strncmp(http_version, "HTTP/", 5) != 0 ||
            http_version[5] < '0' || http_version[5] > '9' ||
            http_version[6] != '.' ||
            http_version[7] < '0' || http_version[7] > '9') {
        return validation;
    }

    if (strcmp(method, "GET") == 0) {
        validation.result = 0;
    }
    else if (strcmp(method, "PUT") == 0) {
        validation.result = 1;
    }
    else if (strcmp(method, "DELETE") == 0) {
        validation.result = 2;
    }
    else if (strcmp(method, "HEAD") == 0) {
        validation.result = 3;
        return validation;
    }
    else if (strcmp(method, "POST") == 0) {
        validation.result = 3;
        return validation;
    }
    else if (strcmp(method, "OPTIONS") == 0) {
        validation.result = 3;
        return validation;
    }
    else if (strcmp(method, "TRACE") == 0) {
        validation.result = 3;
        return validation;
    }
    else if (strcmp(method, "PATCH") == 0) {
        validation.result = 3;
        return validation;
    }
    else if (strcmp(method, "CONNECT") == 0) {
        validation.result = 3;
        return validation;
    }
    else {
        validation.result = -1;
        return validation;
    }

    strncpy(validation.uri, uri, sizeof(validation.uri) - 1);
    validation.uri[sizeof(validation.uri) - 1] = '\0';

    strncpy(temp, str, sizeof(temp) - 1);
    strtok(temp, "\r\n");
    line = strtok(NULL, "\r\n");

    while (line != NULL) {
        if (strlen(line) == 0) {
            break;
        }

        char key[256+1] = {0};
        char value[256+1] = {0};

        if (!parse_key_value(line, key, value)) {
            validation.result = -1;
            return validation;
        }

        if (strcmp(key, "Content-Length") == 0) {
            validation.content_length = atoi(value);
        }

        line = strtok(NULL, "\r\n");
    }

    return validation;
}

/**
2 * Derives a sockaddr_in structure from the provided host and port information.
3 *
4 * @param host The host (IP address or hostname) to be resolved into a network
address.
5 * @param port The port number to be converted into network byte order.
6 *
7 * @return A sockaddr_in structure representing the network address derived from
the host and port.
8 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;
    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error␣parsing␣host/port");
        exit(EXIT_FAILURE);
    }
    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *) result_info->ai_addr);
    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

char *substr(const char *str, const size_t from, const size_t to) {
    const size_t sub_len = to - from;
    char *substring = malloc(sub_len+1);
    strncpy(substring, str + from, sub_len);
    substring[sub_len] = '\0';
    return substring;
}

typedef struct {
    char *key;
    char *value;
} KeyValuePair;

int SIZE = 0;
KeyValuePair RESOURCES[MAX_SIZE] = {0};

/**
 * @return 1 falls neu und 0 falls ersetzt
 */
int my_put(KeyValuePair arr[], const char *key, const char *value) {
    for (int i = 0; i < MAX_SIZE; i++) {
        if (arr[i].key != NULL && strcmp(arr[i].key, key) == 0) {
            free(arr[i].value);
            arr[i].value = strdup(value);
            return 0;
        }
    }

    arr[SIZE].key = strdup(key);
    arr[SIZE].value = strdup(value);
    SIZE++;
    return 1;
}

/**
 * @return 1 falls vorhanden und gelöscht, 0 falls nicht gefunden
 */
int my_delete(KeyValuePair arr[], const char *key) {
    for (int i = 0; i < MAX_SIZE; i++) {
        if (arr[i].key != NULL && strcmp(arr[i].key, key) == 0) {
            arr[i].key = NULL;
            arr[i].value = NULL;
            return 1;
        }
    }
    return 0;
}

char* my_get(KeyValuePair arr[], const char *key) {
    for (int i = 0; i < MAX_SIZE; i++) {
        if (arr[i].key != NULL && strcmp(arr[i].key, key) == 0) {
            return arr[i].value;
        }
    }
    return NULL;
}

UDP_Packet decode_udp_payload(const char *buf) {
    UDP_Packet lookup;
    struct in_addr node_ip_bin;

    memcpy(&lookup.message_type, buf, 1);
    memcpy(&lookup.hash_id, buf + 1, 2);
    memcpy(&lookup.node_id, buf + 3, 2);
    memcpy(&node_ip_bin, buf + 5, 4);
    memcpy(&lookup.node_port, buf + 9, 2);

    lookup.hash_id = ntohs(lookup.hash_id);
    lookup.node_id = ntohs(lookup.node_id);
    lookup.node_port = ntohs(lookup.node_port);

    inet_ntop(AF_INET, &node_ip_bin, lookup.node_ip, INET_ADDRSTRLEN);

    return lookup;
}
void udp_lookup_payload(char *buf, const int hash, const NodeInfo *node_info) {
    uint8_t message_type = 0;
    uint16_t hash_id = htons(hash);
    uint16_t node_id = htons(node_info->node_id);
    uint16_t node_port = htons(node_info->node_port_int);

    const char *node_ip = node_info->succ_ip;
    struct in_addr node_ip_bin;
    inet_pton(AF_INET, node_ip, &node_ip_bin);

    memcpy(buf, &message_type, 1);
    memcpy(buf + 1, &hash_id, 2);
    memcpy(buf + 3, &node_id, 2);
    memcpy(buf + 5, &node_ip_bin, 4);
    memcpy(buf + 9, &node_port, 2);
}

void udp_reply_payload(char *buf, const NodeInfo *node_info, bool i_know_succ_is_responsible) {
    uint8_t message_type = 1;
    uint16_t hash_id = i_know_succ_is_responsible ? htons(node_info->node_id) : htons(node_info->pred_id);
    uint16_t node_id = i_know_succ_is_responsible ? htons(node_info->succ_id) : htons(node_info->node_id);
    uint16_t node_port = i_know_succ_is_responsible ? htons(node_info->succ_port) : htons(node_info->node_port_int);
    const char *node_ip = i_know_succ_is_responsible ? node_info->succ_ip : node_info->node_ip;
    struct in_addr node_ip_bin;
    inet_pton(AF_INET, node_ip, &node_ip_bin);

    memcpy(buf, &message_type, 1);
    memcpy(buf + 1, &hash_id, 2);
    memcpy(buf + 3, &node_id, 2);
    memcpy(buf + 5, &node_ip_bin, 4);
    memcpy(buf + 9, &node_port, 2);
}

void udp_lookup(const int sock, const NodeInfo *node_info, const void *payload, size_t payload_size) {
    char port[20] = {0};
    sprintf(port, "%d", node_info->succ_port);
    struct sockaddr_in dest_addr = derive_sockaddr(node_info->succ_ip, port);

    sendto(sock, payload, payload_size, 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr));
}

void udp_reply(const int sock, struct sockaddr_in addr, const void *payload, size_t payload_size) {
    sendto(sock, payload, payload_size, 0,
               (struct sockaddr*)&addr, sizeof(addr));
}

bool am_i_responsible(const uint16_t hash, const NodeInfo *node_info) { // TODO test_immediate_dht
    if (node_info->pred_id == node_info->succ_id && node_info->node_id == node_info->pred_id)
        return true;

    return node_info->pred_id <= node_info->node_id ?
            hash <= node_info->node_id && hash > node_info->pred_id :
            hash <= node_info->node_id || hash > node_info->pred_id;
}

bool is_my_succ_responsible(const uint16_t hash, const NodeInfo *node_info) {
    return node_info->succ_id >= node_info->node_id ?
            hash > node_info->node_id && hash <= node_info->succ_id :
            hash > node_info->node_id || hash <= node_info->succ_id;
}

bool who_is_responsible(const int tcp_sock, const int udp_sock, const ValidationResult validation, const NodeInfo *this_node_info) {
    // +++ See Other
    const uint16_t hash = pseudo_hash((const unsigned char*)validation.uri, strlen(validation.uri));

    if (am_i_responsible(hash, this_node_info)) {
        printf("%s: YES - I AM\n", MY_PORT);
        fflush(stdout);
        return true;
        // char payload[1 + 2 + 2 + 4 + 2] = {0};
        // udp_reply_payload(payload, this_node_info);
        // struct sockaddr_in dest_addr = derive_sockaddr(this_node_info->node_ip, this_node_info->node_port);
        // udp_reply(udp_sock, dest_addr, payload, sizeof(payload));
    } else {
        printf("%s: NO - I AM NOT\n", MY_PORT);

        if (is_my_succ_responsible(hash, this_node_info)) {
            char see_other[4096] = {0};
            // TODO 307 Temporary Redirect wäre gut, denn 303 wechselt zu GET
            printf("%s: ...sending 303 response\n", MY_PORT);
            fflush(stdout);
            sprintf(see_other, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%d%s\r\nContent-Length: 0\r\n\r\n", this_node_info->succ_ip, this_node_info->succ_port, validation.uri);
            send(tcp_sock, see_other, strlen(see_other), 0);
            // close(tcp_sock);
        }
        else {
            UDP_Packet *found = search_reply(hash);

            if (found != NULL) {
                printf("%s: FOUND - TCP\n", MY_PORT);
                printf("%s: ...sending 303 response\n", MY_PORT);
                fflush(stdout);
                char see_other[4096] = {0};
                // TODO 307 Temporary Redirect wäre gut, denn 303 wechselt zu GET
                sprintf(see_other, "HTTP/1.1 303 See Other\r\nLocation: http://%s:%d%s\r\nContent-Length: 0\r\n\r\n", found->node_ip, found->node_port, validation.uri);
                send(tcp_sock, see_other, strlen(see_other), 0);
                // close(tcp_sock);
            }
            else {
                printf("%s: NOT FOUND - TCP\n", MY_PORT);

                // last_hash = hash;

                printf("%s: ...starting lookup - TCP -> %d\n", MY_PORT, this_node_info->succ_port);
                fflush(stdout);

                char payload[1 + 2 + 2 + 4 + 2] = {0};
                udp_lookup_payload(payload, hash, this_node_info);
                udp_lookup(udp_sock, this_node_info, payload, sizeof(payload));

                printf("%s: ...sending 503 response\n", MY_PORT);
                fflush(stdout);

                char *res = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                // char *res = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
                send(tcp_sock, res, strlen(res), 0);
                // close(tcp_sock);


            }


        }
    }
    return false;
}

void handle_tcp_client(const int tcp_sock, const int udp_sock, const NodeInfo *this_node_info) {
    char current_packet[8192+1] = {0};
    const char *DELIMITER = "\r\n\r\n";

    while (1) {
        char buffer[8192+1] = {0};

        ssize_t bytes_received = recv(tcp_sock, buffer, sizeof(buffer) - 1, 0);
        strncat(current_packet, buffer, bytes_received);
        char *header_end = strstr(current_packet, DELIMITER);

        if (bytes_received <= 0) {
            break;
        }

        if (header_end) {
            size_t header_length = header_end - current_packet;
            char headers[header_length + 1];
            strncpy(headers, current_packet, header_length);
            headers[header_length] = '\0';

            char *body = header_end + strlen(DELIMITER);

            ValidationResult validation = validate(headers);

            size_t content_length = validation.content_length > -1 ? validation.content_length : 0;

            size_t received_body_length = strlen(body);
            while (received_body_length < content_length) { // body nicht vollständig
                ssize_t additional_bytes = recv(tcp_sock, buffer, sizeof(buffer) - 1, 0);

                if (additional_bytes <= 0) {
                    break;
                }

                buffer[additional_bytes] = '\0';
                strncat(body, buffer, additional_bytes);
                received_body_length += additional_bytes;
            }

            const char HTTP_RESPONSE_400[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            const char HTTP_RESPONSE_501[] = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            const char HTTP_RESPONSE_404[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

            if (validation.result == -1) {
                send(tcp_sock, HTTP_RESPONSE_400, strlen(HTTP_RESPONSE_400), 0);
            }

            fprintf(stdout, "%s: Handling %d request for %s (%d byte payload)\n", MY_PORT, validation.result, validation.uri, validation.content_length);
            fflush(stdout);

            bool i_am = who_is_responsible(tcp_sock, udp_sock, validation, this_node_info);
            if (!i_am) {
                return;
            }

            if (validation.result == 0) { // GET
                if (strcmp(validation.uri, "/static/foo") == 0) {
                    const char RES[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nFoo";
                    send(tcp_sock, RES, strlen(RES), 0);
                }
                else if (strcmp(validation.uri, "/static/bar") == 0) {
                    const char RES[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nBar";
                    send(tcp_sock, RES, strlen(RES), 0);
                }
                else if (strcmp(validation.uri, "/static/baz") == 0) {
                    const char RES[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nBaz";
                    send(tcp_sock, RES, strlen(RES), 0);
                }
                else {
                    char *resource_name = strstr(validation.uri, "/dynamic/");
                    if (resource_name == NULL) {
                        send(tcp_sock, HTTP_RESPONSE_404, strlen(HTTP_RESPONSE_404), 0);
                        // close(tcp_sock); // broken pipe error
                    } else {
                        resource_name += strlen("/dynamic/");
                        char *data = my_get(RESOURCES, resource_name);
                        if (data == NULL) {
                            send(tcp_sock, HTTP_RESPONSE_404, strlen(HTTP_RESPONSE_404), 0);
                            close(tcp_sock); // -2
                        } else {
                            char res[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ";
                            char response[8192+1];
                            sprintf(response, "%s%ld\r\n\r\n%s", res, strlen(data), data);
                            send(tcp_sock, response, strlen(response), 0);
                            close(tcp_sock);
                        }
                    }
                }
            }

            else if (validation.result == 1) { // PUT
                char *resource_name = strstr(validation.uri, "/dynamic/");
                if (resource_name == NULL) {
                    const char RES[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send(tcp_sock, RES, strlen(RES), 0);
                    close(tcp_sock);
                } else {
                    resource_name += strlen("/dynamic/");
                    int is_new = my_put(RESOURCES, resource_name, body);
                    if (is_new) {
                        const char RES[] = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(tcp_sock, RES, strlen(RES), 0);
                        close(tcp_sock); // -1
                    } else {
                        const char RES[] = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(tcp_sock, RES, strlen(RES), 0);
                        close(tcp_sock);
                    }
                }
            }

            else if (validation.result == 2) { // DELETE
                char *resource_name = strstr(validation.uri, "/dynamic/");
                if (resource_name == NULL) {
                    const char RES[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send(tcp_sock, RES, strlen(RES), 0);
                    close(tcp_sock);
                } else {
                    resource_name += strlen("/dynamic/");
                    int is_deleted = my_delete(RESOURCES, resource_name);
                    if (is_deleted) {
                        const char RES[] = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(tcp_sock, RES, strlen(RES), 0);
                        close(tcp_sock);
                    } else {
                        const char RES[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(tcp_sock, RES, strlen(RES), 0);
                        close(tcp_sock);
                    }
                }
            }

            else {
                send(tcp_sock, HTTP_RESPONSE_501, strlen(HTTP_RESPONSE_501), 0);
            }

            // verschiebe verbleibende daten an anfang und lösche bereits verarbeitetes Paket aus buffer
            size_t processed_length = header_length + strlen(DELIMITER) + content_length;
            memmove(current_packet, current_packet + processed_length, strlen(current_packet) - processed_length + 1);
        }
    }
    close(tcp_sock);
}

static int setup_udp_socket(struct sockaddr_in addr) {
    // +++ Create UDP Socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // +++ Bind UDP Socket
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1){
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}


int main(int argc, char *argv[]) {
    const char *HOST = argv[1];
    const char *PORT = argv[2];

    MY_PORT = PORT;

    int tcp_sock = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in my_addr = derive_sockaddr(HOST, PORT);

    int yes = 1;
    setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    bind(tcp_sock, (struct sockaddr *)&my_addr, sizeof my_addr);

    const int BACKLOG = 10;
    listen(tcp_sock, BACKLOG);

    int udp_sock = setup_udp_socket(my_addr);

    int this_node_id = 0; // TODO eig. 0
    if (argc == 4) {
        this_node_id = atoi(argv[3]);
    }

    NodeInfo node_info = init_node_info(this_node_id,  PORT, HOST);

    printf("%s: waiting for connections...\n", PORT);

    fd_set read_fds;
    int max_fd = tcp_sock > udp_sock ? tcp_sock : udp_sock;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(tcp_sock, &read_fds);
        FD_SET(udp_sock, &read_fds);

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(tcp_sock, &read_fds)) {
            struct sockaddr_storage their_addr;
            socklen_t addr_size = sizeof(their_addr);
            int new_fd = accept(tcp_sock, (struct sockaddr *)&their_addr, &addr_size);

            if (new_fd == -1) {
                perror("accept");
            } else {
                handle_tcp_client(new_fd, udp_sock, &node_info);
                close(new_fd);
            }
        }

        if (FD_ISSET(udp_sock, &read_fds)) { // TODO HIER
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            char buffer[1000] = {0};
            int len = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);

            if (len < 0) {
                perror("recvfrom");
            } else {
                buffer[len] = '\0';
                printf("%s: Received UDP packet <- %d\n", MY_PORT, ntohs(client_addr.sin_port));
            }

            UDP_Packet packet = decode_udp_payload(buffer);
            printf("%s: Message Type: %d\n", MY_PORT, packet.message_type);
            printf("%s: Hash ID: %d\n", MY_PORT, packet.hash_id);
            printf("%s: Node ID: %d\n", MY_PORT, packet.node_id);
            printf("%s: Node IP: %s\n", MY_PORT, packet.node_ip);
            printf("%s: Node Port: %d\n", MY_PORT, packet.node_port);
            fflush(stdout);

            if (packet.message_type == 1) {
                put_reply(packet);
                printf("%s: PUT!\n", MY_PORT);
                fflush(stdout);
            }

            if (packet.message_type == 0) {

                if (am_i_responsible(packet.hash_id, &node_info)) {
                    char lookup_port[6] = {0};
                    sprintf(lookup_port, "%u", packet.node_port);
                    struct sockaddr_in dest_addr = derive_sockaddr(packet.node_ip, lookup_port);
                    char payload[1 + 2 + 2 + 4 + 2] = {0};

                    printf("%s: i am responsible - UDP -> %d\n", MY_PORT, packet.node_port);
                    fflush(stdout);

                    udp_reply_payload(payload, &node_info, false);
                    udp_reply(udp_sock, dest_addr, payload, sizeof(payload));
                }
                else if (is_my_succ_responsible(packet.hash_id, &node_info)) {
                    char lookup_port[6] = {0};
                    sprintf(lookup_port, "%u", packet.node_port);
                    struct sockaddr_in dest_addr = derive_sockaddr(packet.node_ip, lookup_port);
                    char payload[1 + 2 + 2 + 4 + 2] = {0};

                    printf("%s: my succ is responsible - UDP -> %d\n", MY_PORT, packet.node_port);
                    fflush(stdout);

                    udp_reply_payload(payload, &node_info, true);
                    udp_reply(udp_sock, dest_addr, payload, sizeof(payload));
                }
                else {
                    UDP_Packet *found = search_reply(packet.hash_id);

                    if (found != NULL) {
                        printf("%s: FOUND - UDP\n", MY_PORT);
                        char lookup_port[6] = {0};
                        sprintf(lookup_port, "%u", packet.node_port);
                        struct sockaddr_in dest_addr = derive_sockaddr(packet.node_ip, lookup_port);

                        printf("%s: ...sending Reply - UDP -> %d\n", MY_PORT, packet.node_port);
                        fflush(stdout);

                        char payload[1 + 2 + 2 + 4 + 2] = {0};

                        uint8_t message_type = 1;
                        uint16_t hash_id = htons(found->hash_id); // hash_id := pred_id
                        uint16_t node_id = htons(found->node_id);
                        uint16_t node_port = htons(found->node_port);
                        const char *node_ip = found->node_ip;
                        struct in_addr node_ip_bin;
                        inet_pton(AF_INET, node_ip, &node_ip_bin);

                        memcpy(payload, &message_type, 1);
                        memcpy(payload + 1, &hash_id, 2);
                        memcpy(payload + 3, &node_id, 2);
                        memcpy(payload + 5, &node_ip_bin, 4);
                        memcpy(payload + 9, &node_port, 2);

                        udp_reply(udp_sock, dest_addr, payload, sizeof(payload));
                    } else {
                        printf("%s: NOT FOUND - UDP\n", MY_PORT);
                        printf("%s: ...starting lookup - TCP -> %d\n", MY_PORT, node_info.succ_port);
                        fflush(stdout);
                        udp_lookup(udp_sock, &node_info, buffer, 11);
                    }

                }

            }
        }
    }
}
