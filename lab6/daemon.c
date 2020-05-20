					

					/* daemon.c: this is the skeleton
		for a tcp-daemon which listens at some non-privileged tcp
		port and forks offpring or starts offspring threads 
		to handle the requests. The offspring processes-threads
		currently DO *** NO USEFUL WORK *** (in this they are
		simply following the software practices of many commercial
		vendors). They accept characters (e.g. from telnet) and 
		log them to either stdout or (with the "-log" option) to 
		a logfile which includes the process-thread ID of the 
		offspring. Invoke this program via:

		$ daemon [-log]

		It will display the daemon_listen_port number on
		stdout.  Test it by doing a port-specific telnet, ie:

		$ telnet [host_name] [daemon_listen_port]

		When it receives the tcp connection under UNIX it accepts 
		and fork()'s, the parent returning to listen and the 
		new offspring PROCESS handling the tcp connection. 

		When it receives the tcp connection under Windows NT 
		accepts and _beginthread()'s a new THREAD (of the SAME 
		process) which handles the tcp connection.

		The offspring will send an initial message "Ready.." 
		and then simply read bytes from the socket.

		Makefiles are provided as follows:

		makefile.lnx		RedHAT 5.x Makefile
		makefile.unx		DecUnix (alpha) or Ultrix (VAX)
		makefile.vc5		Windows NT with Winsock2 DLL
		makefile.sun	 	SUNOS 4.1.x on SparcStation


						Marc Thomas           */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>		/* for signal() */
#include <errno.h>

#if defined(_WIN95) || defined(_WINNT)

#include <process.h>
#else

#include <sys/wait.h>		/* for wait() */
#endif

/* ------------------------------------------------------------------ */

#include "header.h"	/* OUR header which handles MOST of the
			WinSock/32-bit Unix/64-bit Unix Differences */
#include "startup.h"	/* globals for main module set by the
			code startup.c */
#include "diagnost.h"	/* OUR dump_xxxx() routines and other
			diagnostics */

/* ------------------------------------------------------------------ */

#define	BUFFER_SIZE	2048
#define	MAX_CHILDREN	   4
struct	_offs {		/* Parent keeps offpring info here  */
			   /*	under UNIX	under WinNT */
	int	opid;	   /* 	   OPID		    PPID    */
	int	thread;	   /*         1          THREAD_NO  */
	unsigned long th_handle;
	char	type[16];  /* 	"process" 	  "thread"  */
	SOCKET	msock;		/* -1 = "not valid"       */
	int	portnum;	/* -1 = "not valid"       */
} offspring[ MAX_CHILDREN ];

int	parentpid;	/* PID of parent process = main thread */
SOCKET	listensock;	/* descriptor for tcp service port     */
SOCKET	msgsock;	/* in case of Unix parent this is the
			   LAST accept() value - each offspring
			   process has its OWN value of msgsock */

#define	STDOUT_FILE	0
#define	LOG_FILE	1
int	logto;
int	threadnum;		/* under UNIX this is always 1, under
			   Windows NT we consecutively number threads:
			   1, 2, 3, ... */
#define	PROCESS_TYPE	1

#define	THREAD_TYPE	0
#define THREAD_STACKSIZE	8192
struct	_arglist {
	int	msock;
	int	exec_type;	/* process (1) or thread(0) */
	int	thread_no;
} arglist;		/* structure for dialog_with_telnet()
			arguments */

			/* function Prototypes */
#if defined(_NOPROTO)

	parent_terminate();
	offspring_terminate();
	gracefully_terminate();
	dialog_with_telnet();
	display_offpring();
#else

void	parent_terminate(int dummy);
void	offspring_terminate(int dummy);
void	gracefully_terminate(int dummy);
void	dialog_with_telnet(void *alist);
void	display_offspring(FILE *fp);
#endif

/* ------------------------------------------------------------------ */

#if defined(_NOPROTO)
int main(argc, argv, envp)
int	argc;	
char	*argv[],*envp[];
#else
int main(int argc, char *argv[], char *envp[])
#endif
	{
	struct	sockaddr_in	name, name_msg, caller;
	int	length, ret, i, k;
#if defined(_WIN95) || defined(_WINNT)	
	unsigned long	tmphandle;
#endif

#include "startup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix startup. Main modules
			ALSO require the inclusion of 
				header.h
				startup.h */

/* INITIALIZE AND CHECK COMMAND LINE ***************************** */
	logto = STDOUT_FILE;
	if ( (argc > 1) && (strncmp(argv[1], "-l", 2) == 0) )
		{
		logto = LOG_FILE;
		}
	else if (argc > 1)
		{
		fprintf(stderr, "\ninvocation: ");
		fprintf(stderr, "\n    daemon [-log] \n");
		fflush(stderr);
		return(1);
		}

/* ZERO OFFSPRING INFORMATION ARRAY ******************************* */
	threadnum = 1;
	for (i = 0 ; i < MAX_CHILDREN ; i++)
		{
		offspring[i].opid = 0;	/* OPID=0 means "inactive" */
		offspring[i].thread = 0;/*     =0 means "inactive" */
		offspring[i].th_handle = 0L;
		offspring[i].type[0] = '\0';
		offspring[i].msock = -1;	/* not valid */
		offspring[i].portnum = -1;	/* not valid */
		}

/* SET SOME SIGNAL HANDLERS *************************************** */
#if defined(_WIN95) || defined(_WINNT)
					/* Windows NT *** LACKS *** 
			a number of important signals */
#else
	signal(SIGQUIT, SIG_IGN);	/* since we may occasionally
			run as root it is NOT a good idea to allow
			WRITABLE core dumps */
	signal(SIGCLD, offspring_terminate);	/* this will warn
			us to update our tables since if a child 
			process dies or is terminated we will be 
			sent a signal SIGCLD */
	signal(SIGHUP, parent_terminate);	/* this will tell 
			us to cleanup, close any open sockets and
			exit when we receive a SIGHUP, or.. */
#endif
	signal(SIGINT, parent_terminate);	/* .. CTRL-C, or.. */
	signal(SIGTERM, parent_terminate);	/* .. system is going
			to SINGLE-user mode */

/* CREATE TCP (ie. STREAM) SERVICE SOCKET ************************* */
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	if (listensock < 0)
		{
		perror("receiver: socket() failed. ");
		return(-1);
		}

/* BIND NAME TO SOCKET using portnumber 0 = "host assigned" ******* */
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = INADDR_ANY;  
				/* INADDR_ANY = assigned by system */
	name.sin_port = htons(0);	/* 0 = assigned by system */
	ret = bind(listensock,(struct sockaddr *)&name, sizeof name);
	if (ret < 0)
		{
		perror("receiver: bind() failed. ");
		return(-1);
		}

/* USE GETSOCKNAME  to find out which PORT was assigned (note that since
		we are listening, not connecting, the socket the host 
		field name.sin_addr will be 0) ******************** */
	length = sizeof name;
	ret = getsockname(listensock, (struct sockaddr *)&name, &length);
	if (ret < 0)
		{
		perror("receiver: getsockname() failed. ");
		return(-1);
		}

/* WRITE INITIAL MESSAGE TO CONTROLLING TERMINAL ****************** */
	parentpid = getpid();
	printf("\nparent: own process id: %d ", parentpid);
	printf("\nparent: we will be listening at tcp port: %hu",
		ntohs(name.sin_port));

blockonlisten:
	display_offspring(stdout);   /* display process-thread info */
	fprintf(stdout, "\nparent: blocking at listen().. ");
	fflush(stdout);

/* LISTEN and start ACCEPTING CONNECTIONS ************************* */
	listen(listensock,5);		/* 5 = max. backlog allowed */
		k = sizeof caller;
		msgsock = accept(listensock,
				(struct sockaddr *)&caller,(int *)&k);
			/* the function accept blocks until there is at least
			one connection in the queue of pending requests. it
			then extracts the first connection from the
			queue of pending requests and creates a new
			socket (msgsock) with the same properties as sock.
			the int msgsock is used as a desc. to read and write
			data. if null parameters were used here (i.e.
			(struct sockaddr *)0 and (int *)0) the address
			of the connecting entity would be ignored.  */
		if ((int)msgsock < 0)
			{
			printf(
	"\nparent: listen() interrupted, probable EINTR (errno=%d) ",
				errno);
			fflush(stdout);
			goto blockonlisten;
			}
		else
		  {

/* CHECK IF WE HAVE A FREE SLOT ************************************ */

		  for (i = 0 ; i < MAX_CHILDREN ; i++)
			{
			if (offspring[i].opid == 0) break;
			}
		  if (i >= MAX_CHILDREN)
			{
			fprintf(stderr, 
			  "\nparent: connect refused: NO free slots.");
			fflush(stderr);
			CLOSE_SOCKET(msgsock);
			goto blockonlisten;
			}

#if defined(_WIN95) || defined(_WINNT)	/* NO fork() = OLD TECHNOLOGY
   WINNT ONLY: begin a "thread" ************************************ */

		  sprintf(offspring[i].type, "thread");
		  offspring[i].msock = msgsock;
		  arglist.msock = msgsock;
		  arglist.exec_type = THREAD_TYPE;
		  arglist.thread_no = threadnum;
		  tmphandle = _beginthread(dialog_with_telnet,
			THREAD_STACKSIZE,
			(void *)&arglist);	/* we attempt to
				start the procedure dialog_with_telnet()
				running as a concurrent THREAD */
		  if ((int)tmphandle < 0)	/* failure */
			{
			fprintf(stderr, 
			  "\nparent: _beginthread failed: ");
			fflush(stderr);
			CLOSE_SOCKET(msgsock);
			printf(
			  "\nparent: ending program and exiting.. \n");
			fflush(stdout);
			CLOSE_SOCKET(listensock);

#include "cleanup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix cleanup. */
			return(-1);		/* fatal error */
			}
		  else				/* success */
			{
			fprintf(stderr, 
		"\nparent: _beginthread successful: thread handle=%lu",
				tmphandle);
				/* record offspring process info */
		  	offspring[i].opid = parentpid;
			offspring[i].thread = threadnum;
			offspring[i].th_handle = tmphandle;
			length = sizeof name_msg;
			ret = getsockname(msgsock, 
				(struct sockaddr *)&name_msg, &length);
			offspring[i].portnum = 
				(int)ntohs(name_msg.sin_port);
			fflush(stderr);

			threadnum++;		/* for next thread */
			goto blockonlisten;
			}
#else
/*  UNIX ONLY: fork() a "process" ********************************** */

		  offspring[i].opid = fork();	/* this call makes a
				copy of the parent. it returns 0 to
				the offspring copy and the (new)
				offspring pid to the parent. */
		  if (offspring[i].opid < 0)	/* failure */
			{
			fprintf(stderr, 
			  "\nparent: fork failed: NO offspring created.");
			fflush(stderr);
			CLOSE_SOCKET(msgsock);
			printf(
			  "\nparent: ending program and exiting.. \n");
			fflush(stdout);
			CLOSE_SOCKET(listensock);

#include "cleanup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix cleanup. */
			return(-1);		/* fatal error */
			}

		  if (offspring[i].opid > 0)	/* we are the PARENT
				so we return to listen() and CLOSE our
				copy of the accept socket descriptor */
			{
			fprintf(stderr, 
		"\nparent: fork successful: offspring(OPID=%5d) created.",
				offspring[i].opid);
				/* record offspring process info */
			offspring[i].thread = threadnum;
			sprintf(offspring[i].type, "process");
			offspring[i].msock = msgsock;
			length = sizeof name_msg;
			ret = getsockname(msgsock, 
				(struct sockaddr *)&name_msg, &length);
			offspring[i].portnum = 
				(int)ntohs(name_msg.sin_port);
			fflush(stderr);
			goto blockonlisten;
			}

		  if (offspring[i].opid == 0)	/* we are the OFFSPRING
				so we CALL dialog_with_telnet() */
			{
			sprintf(offspring[i].type, "process");
			offspring[i].msock = msgsock;
			arglist.msock = msgsock;
			arglist.exec_type = PROCESS_TYPE;
			arglist.thread_no = threadnum;
				/* classic "C" - a pointer to void! */	
			dialog_with_telnet((void *)&arglist);
			}
#endif
		 }  /* end of if ((int)msgsock >= 0) */

#include "cleanup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix cleanup. */
	return(0);
	}  /* end of main */

/* -----------------------------------------------------------------
   Utilities used by PARENT main():
			display_offspring()
			parent_terminate()
			offspring_terminate()
   ----------------------------------------------------------------- */

#if defined(_NOPROTO)
	display_offspring(fp)
	FILE 	*fp;
#else
void	display_offspring(FILE *fp)
#endif
			/* This function simply shows the 
		parent-main threads's offspring status table 
		on the FILE *fp. */
	{
	int	i;

	fprintf(fp,		/* display process-thread info */
  "\n\nparent: offspring[]: ");
	fprintf(fp,
    "\n             opid: ");
	for (i = 0 ; i < MAX_CHILDREN ; i++)
			fprintf(fp, " %8d", offspring[i].opid);
	fprintf(fp,
    "\n        thread no: ");
	for (i = 0 ; i < MAX_CHILDREN ; i++)
			fprintf(fp, " %8d", offspring[i].thread);
	fprintf(fp,
    "\n             type: ");
	for (i = 0 ; i < MAX_CHILDREN ; i++)
			fprintf(fp, " %8s", offspring[i].type);
	fprintf(fp,
    "\n      socket desc: ");
	for (i = 0 ; i < MAX_CHILDREN ; i++)
			fprintf(fp, " %8d", offspring[i].msock);
	fprintf(fp,
    "\n      tcp portnum: ");
	for (i = 0 ; i < MAX_CHILDREN ; i++)
			fprintf(fp, " %8d", offspring[i].portnum);
	fflush(fp);
	}  /* end of display_offspring */

/* ----------------------------------------------------------------- */

#if defined(_NOPROTO)
	parent_terminate()
#else
void	parent_terminate(int dummy)
#endif
	{
#if defined(_WIN95) || defined(_WINNT)
	int	i;

#else
	int	i, opid, ostatus;
	signal(SIGCLD, SIG_IGN);	/* INACTIVATE */
#endif
	printf("\nparent: received request to terminate..");
	fflush(stdout);
			/* tell each active child to exit gracefully
		with a SIGTERM and wait for acknowledgement */
	for (i = 0 ; i < MAX_CHILDREN ; i++)
		{
		if (offspring[i].opid > 0)
			{
#if defined(_WIN95) || defined(_WINNT)
			/* CANNOT kill a thread from outside 
			especially when it is BLOCKed in a system
			call - so we close its socket */
			CLOSE_SOCKET(offspring[i].msock);
			printf(
		"\nparent: offspring socket desc %d of thread %d closed", 
			  offspring[i].msock, offspring[i].thread);
			fflush(stdout);
#else
			kill(offspring[i].opid, SIGTERM);
		/* opid should be equal to offspring[i].opid */
			opid = wait(&ostatus);
			printf(
		"\nparent: offspring terminated: OPID=%d,THRD=%d ", 
				opid, offspring[i].thread);
			fflush(stdout);
#endif
			}

		}  /* end of for */

	sleep(3);	/* pause */
		
	CLOSE_SOCKET(listensock);
	printf("\nparent: ..ending program and exiting. \n");
	fflush(stdout);

#include "cleanup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix cleanup. */
	exit(0);
	}  /* end of parent_terminate */

/* ----------------------------------------------------------------- */

#if defined(_NOPROTO)
	offspring_terminate()
#else
void	offspring_terminate(int dummy)
#endif
			/* actually this signal handler will NEVER
		be called under Windows NT since SIGCLD is NOT
		supported */
	{
#if defined(_WIN95) || defined(_WINNT)
	int	i, opid;

#else
	int	i, opid, ostatus;
	opid = wait(&ostatus);
#endif
	for (i = 0 ; i < MAX_CHILDREN ; i++)
		{
		if (opid == offspring[i].opid)
			{
			offspring[i].opid = 0;	/* no longer active */
			offspring[i].thread = 0;
			offspring[i].th_handle = 0L;
			offspring[i].type[0] = '\0';
			CLOSE_SOCKET(offspring[i].msock);
			offspring[i].msock = -1;
			offspring[i].portnum = -1;
			}
		}

	printf("\nparent: offspring terminated: OPID=%d ", opid);
	fflush(stdout);
					
#if defined(_WIN95) || defined(_WINNT)

#else
	signal(SIGCLD, offspring_terminate);	/* RESET handler */
#endif
	}  /* end of offspring_terminate */

/* -----------------------------------------------------------------
   Utilities used by OFFSPRING main():
			gracefully_terminate()
			dialog_with_telnet()
   ----------------------------------------------------------------- */

SOCKET	gt_msock;
FILE	*gt_logf;
int	gt_opid;
char	gt_logfname[64];

#if defined(_NOPROTO)
	gracefully_terminate()
#else
void	gracefully_terminate(int dummy)
#endif
			/* this allows an offspring PROCESS (but
		NOT a thread) to trap SIGTERM and clean-up its logfile, 
		etc. before exiting. */
	{
	int	ret;

	ret = fprintf(gt_logf,
	  "\n  offspring(OPID=%5d): received request to terminate..",
		gt_opid);
	fflush(gt_logf);

	ret = fprintf(gt_logf,
	  "\n  offspring(OPID=%5d): closing %s and exiting. \n",
		gt_opid, gt_logfname);
	fflush(gt_logf);

	fclose(gt_logf);
	CLOSE_SOCKET(gt_msock);		/* close socket */

#include "cleanup.c"		/* We have written this code to make
			it EASIER to reconcile Winsock 1.1/2.0 to
			(the MUCH easier) Unix cleanup. */
	exit(0);
	}  /* gracefully_terminate */

/* ------------------------------------------------------------------ */

#if defined(_NOPROTO)
	dialog_with_telnet(alist)
	char	*alist;
#else
void	dialog_with_telnet(void *alist)
#endif
			/* This function runs does the main work of
		the daemon and runs in two different modes depending 
		on the values it gets from *alist (the void pointer 
		is given for TYPE consistency when running as a 
		THREAD under Windows NT):

		struct	_arglist {
			int	msock;
			int	exec_type;	
			int	thread_no;
		} *alist;

		If exec_type == 0 it runs as a THREAD and if
		exec_type == 1 it runs as a PROCESS (and is_process
		is set to TRUE).

		It DOES NO USEFUL WORK but simply looks at the global 
		logto and either logs to stdout (logto == STDOUT_FILE) 
		or opens and writes to a log file (logto == LOG_FILE) */
	{
	FILE	*logf;
	char	logfname[64];
	char	buf[BUFFER_SIZE];
	struct	_arglist *argstruct;
	int	opid, is_process, rdsize, ret, i, dmsock, thrdnum;

	  argstruct = (struct _arglist *)alist;	/* set pointer to the
					argument list structure */
	  if (argstruct->exec_type == PROCESS_TYPE)
		is_process = 1;		/* we are a SEPARATE process */
	  else
		is_process = 0;		/* we are a CONCURRENT thread */
	  if (logto == STDOUT_FILE)
	  	sleep(3);

	/* PROCESS ARGUMENT LIST AND MAKE COPIES (before main()
		calls _beginthread() again) ************************* */
		dmsock = argstruct->msock;
		thrdnum = argstruct->thread_no;

	/* GET OUR PROCESS ID *************************************** */
	  if (is_process) opid = getpid();
	  	else opid = parentpid;		/* same as parent*/

	/* POSSIBLY SET SOME SIGNAL HANDLERS ************************ */
	  if (is_process)
		{
#if defined(_WIN95) || defined(_WINNT)
						/* non-main theads
				should *** NOT *** set signal handlers */
#else
	  	signal(SIGQUIT, SIG_IGN);	/* block CTRL-\ */
	  	signal(SIGHUP,  SIG_IGN);
	  	signal(SIGINT,  SIG_IGN);	/* block CTRL-C */
	  	signal(SIGTERM, gracefully_terminate);	
#endif
					/* copy for gracefully_terminate */
		gt_msock = dmsock;
		gt_opid = opid;	
		}

	/* POSSIBLY CLOSE SOME FILE, SOCKET, ETC. DESCRIPTORS ******* */
	  if (is_process)
	  	fclose(stdin);		/* close unused descriptors */

	/* POSSIBLY CHDIR TO ANOTHER DIRECTORY ********************** */

	/* IF WE ARE RUNNING AS ROOT POSSIBLY CHANGE EUID *********** */

	/* POSSIBLY OPEN LOG FILE *********************************** */
	  if (is_process)
		sprintf(logfname, "d%d.log", opid);
	  else
		sprintf(logfname, "dthr%d.log", thrdnum);
	  if (logto == LOG_FILE)
		{				
		logf = fopen(logfname, "w");
		if (logf == (FILE *)NULL)
			{
			fprintf(stderr,
  "\n  offspring(OPID=%5d): fopen(%s,\"w\") failed, logging to stdout. ",
					opid, logfname);
			sprintf(logfname, "stdout");
			logto = STDOUT_FILE;
			logf = (FILE *)stdout;
			}
		else if (is_process)
			{
			fclose(stdout);	/* close unused descriptors */
			}
		}  /* end of if (logto == LOG_FILE) */
	  else
		{
		sprintf(logfname, "stdout");
		logf = (FILE *)stdout;
		}
	  if (is_process)
		{
					/* copy for gracefully_terminate */
		gt_logf = logf;	
		strcpy(gt_logfname, logfname);
		}

	  if (is_process)
	  	fprintf(logf,
	"\n\n  offspring(OPID=%5d,THRD=%2d): after fork(). \n", 
			opid, thrdnum);
	  else
	  	fprintf(logf,
	"\n\n  offspring(OPID=%5d,THRD=%2d): after _beginthread(). \n", 
			opid, thrdnum);
	  fprintf(logf,
	"\n        offspring(OPID=%5d)-->valid connection: ", opid);
	  fflush(logf);

	/* START DIALOG WITH CALLER ********************************* */
			/* let telnet or other tcp caller know we are 
			ready by writing a short message */
	  sprintf(buf, "Ready(OPID=%5d,THRD=%2d).\r\n", opid, thrdnum);
	  send(dmsock, buf, strlen(buf), 0);
		 

 
	/* IN A *** REAL *** DAEMON THIS NEXT SECTION WOULD 
		BE REPLACED BY SOMETHING *** USEFUL *** ************* */



	  rdsize = sizeof(buf) - 1;
	  do	{
		bzero(buf, sizeof buf);	/* zero buffer */

		ret = recv(dmsock, buf, rdsize, 0);
		if (ret < 0)
			{
			fprintf(logf,
	"\n  offspring(OPID=%5d): recv() failed.. dmsock probably closed.", 
				opid);
			fflush(logf);
			goto finish;
			}
		if (ret == 0)
			{
			fprintf(logf,
	"\n        offspring(OPID=%5d)-->sender has ended connection.",
					opid);
			fflush(logf);
			goto finish;
			}
		else
			{
			/* check buffer and change EOL to EOS */
			for (i = 0 ; i < ret ; i++)
			  if ( (buf[i] == '\n') || (buf[i] == '\r') )
				buf[i] = '\0';
			fprintf(logf,
	"\n        offspring(OPID=%5d)-->%s ", opid, buf);
			}
		} while (ret > 0);



	/* CLEAN UP and EXIT **************************************** */
finish:
	CLOSE_SOCKET(dmsock);		/* close socket */
	fprintf(logf,
  "\n  offspring(OPID=%5d,THRD=%2d): ending session and exiting.\n",
			opid, thrdnum);
	fflush(logf);
	if (!is_process)	/* Since there is NO support for
			sending a SIGNAL to the parent-main thread we
			need to reset the table entry OURSELVES so that 
			there will be space for a new thread */
		{
				/* Currently our attempts to *** ALERT ***
			the main-thread that we are terminating have been 
			defeated by Microsoft's on-line documentation */
#if defined(_WIN95) || defined(_WINNT)

#endif
				/* Make SURE we are removed from
			the main-thread's offspring[] table.. */
		for (i = 0 ; i < MAX_CHILDREN ; i++)
			{
			if (thrdnum == offspring[i].thread)
				{
				offspring[i].opid = 0;	/* no longer active */
				offspring[i].thread = 0;
				offspring[i].th_handle = 0L;
				offspring[i].type[0] = '\0';
				offspring[i].msock = -1;
				offspring[i].portnum = -1;
				break;
				}
			}
		if (i < MAX_CHILDREN)
			fprintf(logf,
  "\n  offspring(OPID=%5d,THRD=%2d): manually zeroed offspring[%d].\n",
				opid, thrdnum, i);
	  	if (logto == LOG_FILE)
			display_offspring(logf); 
		fflush(logf);
		}
	if (logto == LOG_FILE)		/* if logging to file, close */
		fclose(logf);
	}  /* end of dialog_with_telnet */

