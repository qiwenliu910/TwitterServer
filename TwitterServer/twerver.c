#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 52826
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: "
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
    int following_num;
    int follower_num;
    int msg_num;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);
int change_follow(struct client *p, struct client *follow, int flag);
void terminate(struct client *p, struct client **active_clients);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client *active_clients, char *s) {
    struct client *curr_client = active_clients;
    while (curr_client != NULL) {
        if (write(curr_client->fd, s, strlen(s)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", curr_client->username);
            remove_client(&active_clients, curr_client->fd);
        }
        curr_client= curr_client->next;
    }
}

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr) {

    struct client* p = new_clients_ptr[0];

    if (p->fd == c->fd) { // client is at the start of the new clients list
        *new_clients_ptr = p->next;
    }
    else{
        while (p->next != NULL) { //remove client from new clients list
            if (p->next->fd == c->fd) {
                p->next = p->next->next;
                break;
            }
            p = p->next;
        }
    }

    // add c to active_clients
    c->next = *active_clients_ptr;
    *active_clients_ptr = c;
}


// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    p->following_num = 0;
    p->follower_num = 0;
    p->msg_num = 0;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // TODO: Remove the client from other clients' following/followers
        // lists
        struct client *c = *p;
        int following_number = c->following_num;
        int followers_number = c->follower_num;
        for (int i = 0; i < following_number; i++) {
            printf("%s is no longer following %s because they disconnected\n", c->username, c->following[0]->username);
            change_follow(c, c->following[0], 1);
            
        }
        for (int j = 0; j < followers_number; j++) {
            printf("%s no longer has %s as a follower\n", c->username, c->followers[0]->username);
            change_follow(c->followers[0], c, 1);
        }
        // Remove the client
        printf("Disconnect from %s\n", inet_ntoa((*p)->ipaddr));
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}
/* 
 * Check if the new_username is available to use.
 * Return 0 if it is, 1 if it's not.
 */
int check_username(char* new_username, struct client *active_clients) {

    struct client *p = active_clients;
    if (strcmp(new_username, "") == 0) { //client has entered an empty string
        return 1;
    }

    while (p != NULL) {
        if (strcmp(p->username, new_username) == 0) { //username already in used
            return 1;
        }
        p = p->next;    
    }
    return 0;
}   

/*
 * Search the first n characters of buf for a network newline (\r\n).
 * Return one plus the index of the '\n' of the first network newline,
 * or -1 if no network newline is found.
 * reuse the code from lab 10
 */
int find_network_newline(const char *buf, int n) {
    for (int i = 0; i < n - 1; i++) {
        if(buf[i] == '\r' && buf[i + 1] == '\n') {
            return i + 2;
        }
    }
    return -1;
}

/* 
 * read inputs from clients 
 * reuse the code from ;lab 10
 * read command if flag is 0, read username if flag is 1
 * return 0 on success and 1 on failure
 */
int read_input(struct client *p, struct client *active_clients, int flag) {
    // Receive messages
        char buf[BUF_SIZE] = {'\0'};
        int inbuf = 0;           
        int room = sizeof(buf);  
        char *after = buf;       

        int nbytes;

        while ((nbytes = read(p->fd, after, room)) > 0) {

            inbuf = inbuf + nbytes;

            printf("[%d] Read %d bytes\n", p->fd, nbytes);

            int where;

            while ((where = find_network_newline(buf, inbuf)) > 0) {
                
                buf[where - 2] = '\0';

                printf("[%d] Found newline: %s\n", p->fd, buf);

                if (strlen(buf) == 0 && flag == 0) { //no enter command
                    strcpy(p->inbuf, "invalid");
                    return 0;
                }
                if (flag == 0) {  // read command
                    strcpy(p->inbuf, buf);
                    return 0;
                }
                else if (flag == 1) { // read username
                    if (check_username(buf, active_clients) == 0) {
                        strcpy(p->username, buf);
                        return 0;
                    }
                    else {
                        return 1;
                    }
                }
                memmove(buf, buf + where, BUF_SIZE - where);
                inbuf = inbuf - where;

            }
            after = buf + inbuf;
            room = BUF_SIZE - inbuf;

        }
    return 1;
}

/* 
 * check if p is trying to follow themselves or duplicate clients
 * return 1 if new_username is valid, 0 otherwise
 */
int check_following(struct client *p, char *new_username) {

    if (strcmp(p->username, new_username) == 0) { //following themselves
        return 0;
    }
    
    for (int i = 0;  i < p->following_num; i++) {
        if (strcmp(p->following[i]->username, new_username) == 0) { //already following
            return 0;
        }
    }
    return 1; 
}
/* 
 * check if p is trying to unfollow themselves or its followers list is empty
 * return 1 if new_username is valid, 0 otherwise
 */
int check_unfollowing(struct client *p, char *new_username) {

    if (strcmp(p->username, new_username) == 0) { //following themselves
        return 0;
    }
    if (p->following_num == 0) { //empty following list
        return 0;
    }
    return 1;
}
/* 
 * p disconnected, remove p from active_clients and notify all the active clients
 */
void terminate(struct client *p, struct client **active_clients) {
    char message[BUF_SIZE];
    printf("%s has left\n", p->username);
    strcpy(message, p->username);
    strcat(message, " has left\r\n");
    remove_client(active_clients, p->fd);
    announce(*active_clients, message);
}

/* 
 * change p and follow's following and followers' s list 
 * p follows follow when flag is 0
 * p unfollows follow when flag is 1
 * return 0 is successfully changed, 1 otherwise
 */
int change_follow(struct client *p, struct client *follow, int flag) {
    if (flag == 0) { //follow
        p->following[p->following_num] = follow; //add follow to p's following list
        follow->followers[follow->follower_num] = p; //add p to follow's follower's list
        p->following_num++;
        follow->follower_num++;
        printf("%s: follow %s\n", p->username, follow->username);
        printf("%s is following %s\n", p->username, follow->username);
        printf("%s has %s as a follower\n", follow->username, p->username);
        return 0;
    }

    else if (flag == 1) { // unfollow
        for (int i = 0; i < p->following_num; i++) {
            if (p->following[i]->fd == follow->fd) { // find follow in p's following list
                for (int k = i; k < p->following_num - 1; k++) {
                    p->following[k] = p->following[k + 1]; // shift all users in p's following list 
                                                           // after follow one to the left
                }
            }
        }
        for (int j = 0; j < follow->follower_num; j++) { 
            if (follow->followers[j]->fd == p->fd) { // find p in follow's followers's list
                for (int m = j; m < follow->follower_num - 1; m++) { 
                    follow->followers[m] = follow->followers[m + 1]; // shift all users in follow's followers list 
                }                                                    // after p one to the left
            }
        }
        p->following_num--;
        follow->follower_num--;
        printf("%s: unfollow %s\n", p->username, follow->username);
        printf("%s no longer has %s as a follower\n", follow->username, p->username);
        printf("%s unfollow %s\n", p->username, follow->username);
        return 0;
    }
    return 1;
}

/* 
 * p follows username in buf, add username to p's following list 
 * and add p to username's list of followers.
 * p can follow up to FOLLOW_LIMIT users and username can have up to FOLLOW_LIMIT followers. 
 * If either of those lists have insufficient space, then p cannot follow username, and should be notified of that.
 * If unsuccessful (e.g., username is not an active user), notify p who issued the command.
 */
void follow(struct client *p, char *buf, struct client **active_clients_list) {

    // get the username of the the follower
    int length = strlen(buf) - 6;
    char follow_name[length];
    memcpy(follow_name, &buf[7], length -1);
    follow_name[length - 1] = '\0';
    int flag = 0;

    if (check_following(p, follow_name) == 0) { //check if trying to follow themselves or double follow
        char *message = "Invalid username!\r\n";
        if (write(p->fd, message, strlen(message)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", p->username);
            terminate(p, active_clients_list);
        }
    }
    else {
        struct client *follow; //check if follow exists in active clients
        for (follow = *active_clients_list; follow != NULL; follow = follow->next) {
            if (strcmp(follow->username, follow_name) == 0) {
                flag = 1;
                break;
            }
        }
        if (flag == 0) { //invalid username
            char *message = "Invalid username!\r\n";
            if (write(p->fd, message, strlen(message)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", p->username);
                terminate(p, active_clients_list);
            }
        }
        else if (flag == 1 && p->following_num < FOLLOW_LIMIT && follow->follower_num < FOLLOW_LIMIT) {

            if (change_follow(p, follow, 0) == 1) { // change the two lists
                char *message= "unsuccessful\r\n";
                if (write(p->fd, message, strlen(message)) == -1){
                    fprintf(stderr, "Write to client %s failed\n", p->username);
                    terminate(p, active_clients_list);
                }
            }
        } //insufficient space for more following or followers
        else if (p->following_num >= FOLLOW_LIMIT || follow->follower_num >= FOLLOW_LIMIT) {
            char *message = "insufficient space for new following\r\n";
            if (write(p->fd, message, strlen(message)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", p->username);
                terminate(p, active_clients_list);
            }
        }
    }
}

/* 
 * p unfollows username in buf, remove username from p's following list, 
 * and remove p from username's list of followers. 
 */
void unfollow(struct client *p, char *buf, struct client **active_clients_list) {

    // get the username in buf
    int length = strlen(buf) - 8;
    char follow_name[length];
    memcpy(follow_name, &buf[9], length -1);
    follow_name[length - 1] = '\0';

    int flag = 0;
    struct client *follow;
    if (check_unfollowing(p, follow_name) == 0) { //check if trying to unfollow themselves
        char *message = "Invalid username!\r\n";
        if (write(p->fd, message, strlen(message)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", p->username);
            terminate(p, active_clients_list);
        }
    }
    else { //find the unfollow in active clients
        for (follow = *active_clients_list; follow != NULL; follow = follow->next) {
            if (strcmp(follow->username, follow_name) == 0) {
                flag = 1;
                break;
            }
        }
        if (flag == 1) {
            if (change_follow(p, follow, 1) == 1) { //remove each other
                char *message = "unsuccessful\r\n";
                if (write(p->fd, message, strlen(message)) == -1) {
                    fprintf(stderr, "Write to client %s failed\n", p->username);
                    terminate(p, active_clients_list);
                }
            }
        }
        else {
            char *message = "Invalid username!\r\n";
            if (write(p->fd, message, strlen(message)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", p->username);
                terminate(p, active_clients_list);
            }
        }
    }

}

/* 
 * Displays the previously sent messages of those users this p is following.
 */
void show(struct client *p, struct client **active_clients_list) {
    char message[BUF_SIZE];
    printf("%s :show\n", p->username);  
    for (int i = 0; i < p->following_num; i++) { 
        for (int j = 0; j < p->following[i]->msg_num; j++) {
            strcpy(message, p->following[i]->username);
            strcat(message, " wrote: ");
            strcat(message, p->following[i]->message[j]);
            strcat(message,"\r\n");
            if (write(p->fd, message, strlen(message)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", p->username);
                terminate(p, active_clients_list);
            }
        }    
    }   
}

/* 
 * send message to all client p's followers
 * If p has already sent MSG_LIMIT messages, notify p who issued the command and do not send the message.
 */
void send_message(struct client *p, char *buf, struct client **active_clients_list) {
    
    //get the message from the sender
    int length = strlen(buf) - 4;
    char message[length];
    memcpy(message, &buf[5], length - 1);
    message[length - 1] = '\0';

    // format the message to include the username of the sender
    char msg[BUF_SIZE];
    strcpy(msg, p->username);
    strcat(msg, ": ");
    strcat(msg, message);
    strcat(msg, "\r\n");

    if (p->msg_num >= MSG_LIMIT) {
        char *note = "message limit reached.\r\n";
        if (write(p->fd, note, strlen(note)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", p->username);
            terminate(p, active_clients_list);
        }
    }
    else { // send message to all its followers
        for (int i = 0; i < p->follower_num; i++) {
            if(write(p->followers[i]->fd, msg, strlen(msg)) == -1) {
                fprintf(stderr, "Write to client %s failed\n", p->username);
                terminate(p, active_clients_list);
            }
        }
        strcpy(p->message[p->msg_num], message);
        p->msg_num++;
    }
    printf("%s: send %s\n", p->username, message);
}

/* 
 * Check which command is isssued and executes the corresponding helper function
 */
void check_command(struct client *p, char *buf, struct client **active_clients_list) {

    // get the command
    char temp[BUF_SIZE];
    strcpy(temp, buf);
    char* command = strtok(temp, " ");

    // check which command is issued
    if ((strcmp(command, FOLLOW_MSG) == 0) && (strlen(buf) >= strlen(FOLLOW_MSG) + 2)){
        follow(p, buf, active_clients_list);
    }
    else if ((strcmp(command, UNFOLLOW_MSG) == 0 && (strlen(buf) >= strlen(UNFOLLOW_MSG) + 2))) {
        unfollow(p, buf, active_clients_list);
    }
    else if ((strcmp(command, SHOW_MSG) == 0) && (strlen(buf) == strlen(SHOW_MSG))) {
        show(p, active_clients_list);
    }
    else if ((strcmp(command, SEND_MSG) == 0) && (strlen(buf) >= strlen(SEND_MSG) + 2)) {
        send_message(p, buf, active_clients_list);
    }
    else if ((strcmp(command, "quit") == 0) && (strlen(buf) == 4)) {
        terminate(p, active_clients_list);

    }
    else {
        char *message = "Invalid Command\r\n";
        printf("%s issued an invalid commmand\n", p->username);
        if (write(p->fd, message, strlen(message)) == -1) {
            fprintf(stderr, "Write to client %s failed\n", p->username);
            terminate(p, active_clients_list);
        }
    }
}

int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled;
        char message[BUF_SIZE];
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // TODO: handle input from a new client who has not yet
                        // entered an acceptable name
                        
                        int join_result = read_input(p, active_clients,  1);
                       
                        if (join_result == 0) {

                            strcpy(message, p->username);
                            strcat(message, " has just joined\r\n");
                            printf("%s has just joined.\n", p->username);
                            activate_client(p, &active_clients, &new_clients);
                            announce(active_clients, message);
                        }
                        else if(join_result == 1) {
                            printf("A user has entered an invalid username\n");
                            char *greeting = "Please enter your username again!\r\n";
                            if(write(p->fd, greeting, strlen(greeting)) == -1) {
                                fprintf(stderr, "Write to client %s failed\n", p->username);
                                remove_client(&new_clients, p->fd);
                            }
                        }
                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // TODO: handle input from an active client
                            
                            int read_result = read_input(p, active_clients, 0); 

                            if (read_result == 1) { // client disconnected
                                fprintf(stderr, "Read from client %s failed\n", p->username);
                                terminate(p, &active_clients);
                            }
                            else {
                                printf("%s has just issued a command.\n", p->username);  
                                check_command(p, p->inbuf, &active_clients);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
