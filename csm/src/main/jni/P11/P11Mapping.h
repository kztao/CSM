
#include <iostream>
#include <map>
#include <set>

#include "cryptoki.h"

#define INDEX_SLOTID CK_SLOT_ID
#define INDEX_SESSIONHANDLE CK_SESSION_HANDLE

using std::string;
using std::set;

typedef struct slotIDServer
{
	string des;
	CK_SLOT_ID slotID;
}slotIDServer;

typedef struct sessionServer
{
	string des;
	CK_SESSION_HANDLE handle;
}sessionServer;

typedef struct slotIDStatus{
	slotIDServer slotIDServer1;
	CK_STATUS_ENUM statusEnum;
}slotIDStatus;

class P11Mapping
{
private:
public:
	P11Mapping();
	virtual ~P11Mapping();

    void AddSlot(slotIDServer server);
	void DelSlot(INDEX_SLOTID slotId) ;
	void DelSlot(string des);
	int GetSlotCount();
    INDEX_SLOTID GetSlot(int index);
    int GetSlot(INDEX_SLOTID clientslotid,slotIDServer *server);
	int GetIndexByName(string des, INDEX_SLOTID *clientslotid);
	void SetSlotStatus(INDEX_SLOTID slotId,CK_STATUS_ENUM statusEnum);
	int GetSlotStatus(INDEX_SLOTID slotId,CK_STATUS_ENUM_PTR statusEnum);

	INDEX_SESSIONHANDLE AddSession(INDEX_SLOTID slotId,sessionServer server);
	int GetSession(INDEX_SESSIONHANDLE clientsessionhandle,sessionServer *server);	
	int GetSlotFromSession(INDEX_SESSIONHANDLE hsession, INDEX_SLOTID* pClient);
	set<CK_SESSION_HANDLE> ClearSessionbySlot(INDEX_SLOTID slotindex);

};
