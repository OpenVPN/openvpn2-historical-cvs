/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This program allows one or more OpenVPN processes to be started
 * as a service.  To build, you must get the service sample from the
 * Platform SDK and replace Simple.c with this file.
 *
 * You should also apply service.patch to
 * service.c and service.h from the Platform SDK service sample.
 *
 * This code is designed to be built with the mingw compiler.
 */

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <process.h>
#include "service.h"

/* bool definitions */
#define bool int
#define true 1
#define false 0

/* These are new for 2000/XP, so they aren't in the mingw headers yet */
#ifndef BELOW_NORMAL_PRIORITY_CLASS
#define BELOW_NORMAL_PRIORITY_CLASS 0x00004000
#endif
#ifndef ABOVE_NORMAL_PRIORITY_CLASS
#define ABOVE_NORMAL_PRIORITY_CLASS 0x00008000
#endif

/*
 * This event is initially created in the non-signaled
 * state.  It will transition to the signaled state when
 * we have received a terminate signal from the Service
 * Control Manager which will cause an asynchronous call
 * of ServiceStop below.
 */
#define EXIT_EVENT_NAME "openvpn_exit"

static HANDLE exit_event = NULL;

/* clear an object */
#define CLEAR(x) memset(&(x), 0, sizeof(x))

/* snprintf with guaranteed null termination */
#define mysnprintf(out, args...) \
        { \
           snprintf (out, sizeof(out), args); \
           out [sizeof (out) - 1] = '\0'; \
        }

/* write error to event log */
#define ERR(args...) \
        { \
           char x_msg[256]; \
           mysnprintf (x_msg, args); \
           AddToMessageLog (x_msg); \
        }

/* get a registry string */
#define QUERY_REG_STRING(name, data) \
  { \
    len = sizeof (data); \
    status = RegQueryValueEx(openvpn_key, name, NULL, &type, data, &len); \
    if (status != ERROR_SUCCESS || type != REG_SZ) \
      { \
        SetLastError (status); \
        ERR (error_format, name); \
	RegCloseKey (openvpn_key); \
	goto finish; \
      } \
  }

static bool
match (const WIN32_FIND_DATA *find, const char *ext)
{
  int i;

  if (find->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    return false;

  if (!strlen (ext))
    return true;

  i = strlen (find->cFileName) - strlen (ext) - 1;
  if (i < 1)
    return false;

  return find->cFileName[i] == '.' && !strcmp (find->cFileName + i + 1, ext);
}

/*
 * Modify the extension on a filename.
 */
static bool
modext (char *dest, int size, const char *src, const char *newext)
{
  int i;

  if (size > 0 && (strlen (src) + 1) <= size)
    {
      strcpy (dest, src);
      dest [size - 1] = '\0';
      i = strlen (dest);
      while (--i >= 0)
	{
	  if (dest[i] == '\\')
	    break;
	  if (dest[i] == '.')
	    {
	      dest[i] = '\0';
	      break;
	    }
	}
      if (strlen (dest) + strlen(newext) + 2 <= size)
	{
	  strcat (dest, ".");
	  strcat (dest, newext);
	  return true;
	}
      dest [0] = '\0';
    }
  return false;
}

VOID ServiceStart (DWORD dwArgc, LPTSTR *lpszArgv)
{
  char exe_path[MAX_PATH];
  char config_dir[MAX_PATH];
  char ext_string[16];
  char log_dir[MAX_PATH];
  char priority_string[64];
  DWORD priority;

  if (!ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000))
    {
      ERR ("ReportStatusToSCMgr #1 failed");
      goto finish;
    }

  /*
   * Create our exit event
   */
  exit_event = CreateEvent (NULL, TRUE, FALSE, EXIT_EVENT_NAME);
  if (exit_event == NULL)
    {
      ERR ("CreateEvent failed on exit event: %s", EXIT_EVENT_NAME);
      goto finish;
    }

  /*
   * If exit event is already signaled, it means we were not
   * shut down properly.
   */
  if (WaitForSingleObject (exit_event, 0) != WAIT_TIMEOUT)
    {
      ERR ("Exit event is already signaled -- we were not shut down properly");
      goto finish;
    }

  if (!ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000))
    {
      ERR ("ReportStatusToSCMgr #2 failed");
      goto finish;
    }

  /*
   * Read info from registry in key HKLM\SOFTWARE\OpenVPN
   */
  {
    HKEY openvpn_key;
    LONG status;
    DWORD len;
    DWORD type;
    char error_string[256];
    static const char error_format[] = "Error querying registry key of type REG_SZ: HKLM\\SOFTWARE\\OpenVPN\\%s";

    status = RegOpenKeyEx(
			  HKEY_LOCAL_MACHINE,
			  "SOFTWARE\\OpenVPN",
			  0,
			  KEY_READ,
			  &openvpn_key);

    if (status != ERROR_SUCCESS)
      {
	SetLastError (status);
	ERR ("Registry key HKLM\\SOFTWARE\\OpenVPN not found");
	goto finish;
      }

    /* get path to openvpn.exe */
    QUERY_REG_STRING ("exe_path", exe_path);

    /* get path to configuration directory */
    QUERY_REG_STRING ("config_dir", config_dir);

    /* get extension on configuration files */
    QUERY_REG_STRING ("config_ext", ext_string);

    /* get path to log directory */
    QUERY_REG_STRING ("log_dir", log_dir);
y
    /* get priority for spawned OpenVPN subprocesses */
    QUERY_REG_STRING ("priority", priority_string);

    RegCloseKey (openvpn_key);
  }

  /* set process priority */
  priority = NORMAL_PRIORITY_CLASS;
  if (!strcmp (priority_string, "IDLE_PRIORITY_CLASS"))
    priority = IDLE_PRIORITY_CLASS;
  else if (!strcmp (priority_string, "BELOW_NORMAL_PRIORITY_CLASS"))
    priority = BELOW_NORMAL_PRIORITY_CLASS;
  else if (!strcmp (priority_string, "NORMAL_PRIORITY_CLASS"))
    priority = NORMAL_PRIORITY_CLASS;
  else if (!strcmp (priority_string, "ABOVE_NORMAL_PRIORITY_CLASS"))
    priority = ABOVE_NORMAL_PRIORITY_CLASS;
  else if (!strcmp (priority_string, "HIGH_PRIORITY_CLASS"))
    priority = HIGH_PRIORITY_CLASS;
  else
    {
      ERR ("Unknown priority name: %s", priority_string);
      goto finish;
    }

  /*
   * Instantiate an OpenVPN process for each configuration
   * file found.
   */
  {
    WIN32_FIND_DATA find_obj;
    HANDLE find_handle;
    BOOL more_files;
    char find_string[MAX_PATH];

    mysnprintf (find_string, "%s\\*", config_dir);

    find_handle = FindFirstFile (find_string, &find_obj);
    if (find_handle == INVALID_HANDLE_VALUE)
      {
        ERR ("Cannot get configuration file list using: %s", find_string);
	goto finish;
      }

    /*
     * Loop over each config file
     */
    do {
      HANDLE log_handle = NULL;
      STARTUPINFO start_info;
      PROCESS_INFORMATION proc_info;
      SECURITY_ATTRIBUTES sa;
      SECURITY_DESCRIPTOR sd;
      char log_file[MAX_PATH];
      char log_path[MAX_PATH];
      char command_line[256];

      CLEAR (start_info);
      CLEAR (proc_info);
      CLEAR (sa);
      CLEAR (sd);

      if (!ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000))
	{
	  ERR ("ReportStatusToSCMgr #3 failed");
	  FindClose (find_handle);
	  goto finish;
	}

      /* does file have the correct type and extension? */
      if (match (&find_obj, ext_string))
	{
	  /* get log file pathname */
	  if (!modext (log_file, sizeof (log_file), find_obj.cFileName, "log"))
	    {
	      ERR ("Cannot construct logfile name based on: %s", find_obj.cFileName);
	      FindClose (find_handle);
	      goto finish;
	    }
	  mysnprintf (log_path, "%s\\%s", log_dir, log_file);

	  /* construct command line */
	  mysnprintf (command_line, "openvpn --config \"%s\"", find_obj.cFileName);

	  /* Make security attributes struct for logfile handle so it can
	     be inherited. */
	  sa.nLength = sizeof (sa);
	  sa.lpSecurityDescriptor = &sd;
	  sa.bInheritHandle = TRUE;
	  if (!InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION))
	    {
	      ERR ("InitializeSecurityDescriptor failed");
	      FindClose (find_handle);
	      goto finish;
	    }
	  if (!SetSecurityDescriptorDacl (&sd, TRUE, NULL, FALSE))
	    {
	      ERR ("SetSecurityDescriptorDacl failed");
	      FindClose (find_handle);
	      goto finish;
	    }

	  /* open logfile as stdout/stderr for soon-to-be-spawned subprocess */
	  log_handle = CreateFile (log_path,
				   GENERIC_WRITE,
				   FILE_SHARE_READ,
				   &sa,
				   CREATE_ALWAYS,
				   FILE_ATTRIBUTE_NORMAL,
				   NULL);

	  if (log_handle == INVALID_HANDLE_VALUE)
	    {
	      ERR ("Cannot open logfile: %s", log_path);
	      FindClose (find_handle);
	      goto finish;
	    }

	  /* fill in STARTUPINFO struct */
	  GetStartupInfo(&start_info);
	  start_info.cb = sizeof(start_info);
	  start_info.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
	  start_info.wShowWindow = SW_HIDE;
	  start_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	  start_info.hStdOutput = start_info.hStdError = log_handle;

	  /* create an OpenVPN process for one config file */
	  if (!CreateProcess(exe_path,
			     command_line,
			     NULL,
			     NULL,
			     TRUE,
			     priority | CREATE_NEW_CONSOLE,
			     NULL,
			     config_dir,
			     &start_info,
			     &proc_info))
	    {
	      ERR ("CreateProcess failed, exe='%s' cmdline='%s' dir='%s'",
		   exe_path,
		   command_line,
		   config_dir);

	      FindClose (find_handle);
	      CloseHandle (log_handle);
	      goto finish;
	    }

	  /* close unneeded handles */
	  Sleep (1000); /* try to prevent race if we close logfile
			   handle before child process DUPs it */
	  if (!CloseHandle (proc_info.hProcess)
	      || !CloseHandle (proc_info.hThread)
	      || !CloseHandle (log_handle))
	    {
	      ERR ("CloseHandle failed");
	      goto finish;
	    }
	}

      /* more files to process? */
      more_files = FindNextFile (find_handle, &find_obj);

    } while (more_files);
    
    FindClose (find_handle);
  }

  /* we are now fully started */
  if (!ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0))
    {
      ERR ("ReportStatusToSCMgr SERVICE_RUNNING failed");
      goto finish;
    }

  /* wait for our shutdown signal */
  if (WaitForSingleObject (exit_event, INFINITE) != WAIT_OBJECT_0)
    {
      ERR ("wait for shutdown signal failed");
    }

 finish:
  ServiceStop ();
  if (exit_event)
    CloseHandle (exit_event);
}

VOID ServiceStop()
{
  if (exit_event)
    SetEvent(exit_event);
}
