/*
UNIX Daemon Server program for monitoring conntrack logging 
processes. 
Usage:		./vyatta-conntrack-logging 
                  -p <proto-name> -e <events> [-s <proto-state>]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <error.h>
#include <syslog.h>


#define RUNNING_DIR	"/var/run/vyatta"
#define LOCK_FILE	"connlogd.lock"
#define MAX_PROCESS 17
 
// Global variables
pid_t pids[MAX_PROCESS];
char *cmds[MAX_PROCESS];
long int nbuffer[MAX_PROCESS];
int pcounter=0;
long int netlink_buffer_size = 2097152;
long int netlink_buffer_maxsize= 8388608;

// Initialise the nbuffer to 2MB
void init_nbuffer() 
{
  int i;  
  for (i=0;i<MAX_PROCESS;i++) {
    nbuffer[i]=netlink_buffer_size;
  }
  return;
}

//Signal handler for SIGHUP and SIGTERM
void signal_handler(sig)
{
  switch(sig) {
    case SIGHUP:
      openlog("log-conntrack", LOG_PID, LOG_USER);
      syslog(LOG_ALERT,"STOPPING CONNTRACK DAEMON");
      closelog();
      int i;
      for(i=0;i<pcounter;i++) {
        kill(pids[i], SIGKILL); 
      }
      exit(0);
      break;
    case SIGTERM:
      exit(0);
      break;
  }
}

//Create child process to start conntrack logger
void start_child(char *cmd, int index) 
{
  pid_t pid;
  int west;
  int ret;
  
  pid=fork();
  if (pid<0) { 
    perror("Conntrack logging error:");   
    exit(1); /* fork error */
  }
  if (pid==0) {
    pids[index]=getpid();
    openlog("log-conntrack", LOG_PID, LOG_USER);
    syslog(LOG_ALERT, "STARTED PROCESS: %s", cmd);
    closelog();
    ret=system(cmd);
    if (WIFSIGNALED(ret) &&
    (WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT)) {
      exit(0);
    }
    else {
      exit(0);
    }   
  }
  else {
    pids[index]=pid;
  } 
}

//Daemonize the process to run in the background
void daemonize()
{
  int p,i,fptr;
  char str[10];
 
  p=fork();
  if (p<0) {
    perror("Conntrack logging error:"); 
    exit(1);
  }
  if (p>0) {
    exit(0);
  }
  /* child (daemon) continues */
  openlog("log-conntrack", LOG_PID, LOG_USER);
  syslog(LOG_ALERT,"STARTING CONNTRACK DAEMON");
  closelog();
  setsid();
  for (i=getdtablesize();i>=0;--i) 
    close(i); 
  i=open("/dev/null",O_RDWR); dup(i); dup(i);
  umask(027);
  chdir(RUNNING_DIR);
  fptr=open(LOCK_FILE,O_RDWR|O_CREAT,0640);
  if (fptr<0) 
    exit(1);
  if (lockf(fptr,F_TLOCK,0)<0)
    exit(0);
  sprintf(str,"%d\n",getpid());
  write(fptr,str,strlen(str));

  signal(SIGHUP,signal_handler);
  signal(SIGTERM,signal_handler);
}

int main(int argc, char *argv[])
{
  int other=0;
  int i, pid;
  char *conn="conntrack -E";
  char *logger="logger -t log-conntrack -p daemon.notice";
  char *fother="grep -vE 'tcp|udp|icmp'"; 
  char cmd[1024];
  char cmd_to_run[1024]; 
  int length = 0;
  char * temp_cmd = cmd;
       
  for (i=1; i<argc; i++) {
    switch(argv[i][1]) {
      case 'p':
        if (i+1 < argc && argv[i+1][0] != '-') {
          if (strncmp(argv[i+1], "other",
          strlen(argv[i+1])) == 0) {
            other=1;
            snprintf(cmd, sizeof (cmd), "%s", conn);
            length = strlen (cmd); 
            temp_cmd = cmd + length;
            i++;
          } else if ((strncmp(argv[i+1], "tcp",
            strlen(argv[i+1])) == 0) ||
            (strncmp(argv[i+1], "udp",
            strlen(argv[i+1])) == 0) ||
            (strncmp(argv[i+1], "icmp",
            strlen(argv[i+1])) == 0)) {
              snprintf(cmd, sizeof (cmd), "%s%s%s", conn, " -p ", argv[i+1]);
              other=0; 
              length = strlen (cmd);
              temp_cmd = cmd + length;
              i++;
            }
        }
        break;
      case 'e':  
        if (i+1 < argc && argv[i+1][0] != '-') {
          if ((strncmp(argv[i+1], "NEW",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "UPDATES",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "DESTROY",
          strlen(argv[i+1])) == 0)) {
            if (other == 1) {
              snprintf(temp_cmd, sizeof (cmd) - length, "%s%s%s%s%s%s%s%s", " -e ", 
              argv[i+1], " -o id", " -b %d", " | ", fother, " | ", logger);
              cmds[pcounter] = malloc(strlen(cmd)+1);
              strcpy(cmds[pcounter],cmd); 
              pcounter++;
            } else if ((strncmp(argv[i-1], "tcp",strlen(argv[i-1]))==0) &&
              (strncmp(argv[i+1], "UPDATES",strlen(argv[i+1])) == 0)){
                snprintf(temp_cmd, sizeof (cmd) - length, "%s%s", " -e ", argv[i+1]);
            } else {
                snprintf(temp_cmd, sizeof (cmd) - length, "%s%s%s%s%s%s", " -e ", 
                argv[i+1], " -o id", " -b %d", " | ", logger);
                cmds[pcounter] = malloc(strlen(cmd)+1); 
                strcpy(cmds[pcounter],cmd);
                pcounter++;
            }
            length = strlen (cmd);
            temp_cmd = cmd + length;
            i++;
          }
        }
        break;
      case 's': 
        if (i+1 < argc && argv[i+1][0] != '-') {
          if ((strncmp(argv[i+1], "SYN_RECV",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "ESTABLISHED",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "FIN_WAIT",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "CLOSE_WAIT",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "LAST_ACK",
          strlen(argv[i+1])) == 0) ||
          (strncmp(argv[i+1], "TIME_WAIT",
          strlen(argv[i+1])) == 0)) {
            snprintf(temp_cmd, sizeof (cmd) - length, "%s%s%s%s%s%s", " --state ",
            argv[i+1], " -o id", " -b %d", " | ", logger);
            cmds[pcounter] = malloc(strlen(cmd)+1); 
            strcpy(cmds[pcounter],cmd);
            pcounter++;
            length = strlen (cmd);
            temp_cmd = cmd + length;
            i++;
          }
        }
        break;
    }
  }
    // Daemonize the connlog process. 
    daemonize();
        
    // Call to init_nbuffer  
    init_nbuffer();
 
    //Start the conntrack logging processes 
    for(i=0;i<pcounter;i++) {  
      sprintf(cmd_to_run, cmds[i], nbuffer[i]);
      start_child(cmd_to_run,i);
    }
    pid_t dead_child;
    int status; 
    while(dead_child=wait(&status)) {
      for(i=0;i<pcounter;i++) {
        if (pids[i]==dead_child) { 
          sprintf(cmd_to_run, cmds[i], nbuffer[i]);
          openlog("log-conntrack", LOG_PID, LOG_USER);
          syslog(LOG_ALERT, "PROCESS EXITED: %s ", cmd_to_run);
          nbuffer[i] += netlink_buffer_size;
          if (nbuffer[i] <= netlink_buffer_maxsize) {
            sprintf(cmd_to_run, cmds[i], nbuffer[i]);
          } else { 
            nbuffer[i] -= netlink_buffer_size; 
            sprintf(cmd_to_run, cmds[i], nbuffer[i]);
          }
          syslog(LOG_ALERT,"RESTARTING PROCESS (Increase netlink buffer to %d bytes)", nbuffer[i]); 
          closelog(); 
          start_child(cmd_to_run,i);
        }
      }
    }
}

/* EOF */
