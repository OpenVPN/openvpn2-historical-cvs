/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device
 *               functionality on Windows.  Originally derived
 *               from the CIPE-Win32 project by Damion K. Wilson,
 *               with extensive modifications by James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) James Yonan, 2003-2004,
 *  and is released under the GPL version 2 (see below).
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

typedef struct _INSTANCE {
  struct _INSTANCE *next;
  TapAdapterPointer m_Adapter;
} INSTANCE;

INSTANCE *g_Instance_List;
MUTEX g_Instance_List_Lock;

BOOLEAN
InitInstanceList (VOID)
{
  g_Instance_List = NULL;
  INIT_MUTEX (&g_Instance_List_Lock);
  return TRUE;
}

int
NInstances (VOID)
{
  BOOLEAN got_lock;
  int ret = -1;

  ACQUIRE_MUTEX_ADAPTIVE (&g_Instance_List_Lock, got_lock);

  if (got_lock)
    {
      INSTANCE *current;
      ret = 0;
      for (current = g_Instance_List; current != NULL; current = current->next)
	{
	  ++ret;
	}
      RELEASE_MUTEX (&g_Instance_List_Lock);
    }

  return ret;
}

BOOLEAN
AddAdapterToInstanceList (TapAdapterPointer p_Adapter)
{
  BOOLEAN got_lock;
  BOOLEAN ret = FALSE;

  ACQUIRE_MUTEX_ADAPTIVE (&g_Instance_List_Lock, got_lock);

  if (got_lock)
    {
      INSTANCE *i = MemAlloc (sizeof (INSTANCE), FALSE);
      if (i)
	{
	  MYASSERT (p_Adapter);
	  i->m_Adapter = p_Adapter;
	  i->next = g_Instance_List;
	  g_Instance_List = i;
	  ret = TRUE;
	}
      RELEASE_MUTEX (&g_Instance_List_Lock);
    }

  return ret;
}

BOOLEAN
RemoveAdapterFromInstanceList (TapAdapterPointer p_Adapter)
{
  BOOLEAN got_lock;
  BOOLEAN ret = FALSE;

  ACQUIRE_MUTEX_ADAPTIVE (&g_Instance_List_Lock, got_lock);

  if (got_lock)
    {
      INSTANCE *current, *prev=NULL;
      for (current = g_Instance_List; current != NULL; current = current->next)
	{
	  if (current->m_Adapter == p_Adapter) // found match
	    {
	      if (prev)
		prev->next = current->next;
	      else
		g_Instance_List = current->next;
	      MemFree (current->m_Adapter, sizeof (TapAdapter));
	      MemFree (current, sizeof (INSTANCE));
	      ret = TRUE;
	      break;
	    }
	  prev = current;
	}
      RELEASE_MUTEX (&g_Instance_List_Lock);
    }

  return ret;
}

TapAdapterPointer
LookupAdapterInInstanceList (PDEVICE_OBJECT p_DeviceObject)
{
  BOOLEAN got_lock;
  TapAdapterPointer ret = NULL;

  ACQUIRE_MUTEX_ADAPTIVE (&g_Instance_List_Lock, got_lock);

  if (got_lock)
    {
      INSTANCE *current, *prev=NULL;
      for (current = g_Instance_List; current != NULL; current = current->next)
	{
	  if (p_DeviceObject == current->m_Adapter->m_Extension.m_TapDevice) // found match
	    {
	      // move it to head of list
	      if (prev)
		{
		  prev->next = current->next;
		  current->next = g_Instance_List;
		  g_Instance_List = current;
		}
	      ret = g_Instance_List->m_Adapter;
	      break;
	    }
	  prev = current;
	}
      RELEASE_MUTEX (&g_Instance_List_Lock);
    }

  return ret;
}
