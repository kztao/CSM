#include "Mutex.h"
#include "P11Mapping.h"
#include "logserver.h"

static int globeSlotIndex = 0;
static int globeSessionIndex = 1;
using std::map;
using std::make_pair;

static map<INDEX_SLOTID,slotIDServer> slotMap;
static map<INDEX_SESSIONHANDLE,sessionServer> sessionMap;
static map<INDEX_SLOTID ,CK_STATUS_ENUM> statusMap;
static map<INDEX_SESSIONHANDLE ,INDEX_SLOTID> ClientSessionAndSlotMap;


static Mutex mutexSlotID;
static Mutex mutexSession;

static const char* tag = "csm_p11Mapping";
P11Mapping::P11Mapping(){

}

P11Mapping::~P11Mapping(){

}

void P11Mapping::AddSlot(slotIDServer server)
{	
	map<INDEX_SLOTID,slotIDServer>::iterator it;
	
	mutexSlotID.Lock();
	for(it=slotMap.begin();it!=slotMap.end();++it)
	{
		if(!memcmp(&it->second,&server,sizeof(slotIDServer)))
		{	
			LOGSERVERI(tag,"slot is already added");
			mutexSlotID.Unlock();
	
			return;
		}
	}

	slotMap.insert(make_pair(globeSlotIndex,server));

	statusMap[globeSlotIndex] = CK_STATUS_ENUM_UNLOGIN;
	globeSlotIndex++;
	
	mutexSlotID.Unlock();

	LOGSERVERI(tag,"add slot %d(%lu,%s),slotnum: %d", (globeSlotIndex-1), server.slotID,server.des.data(),slotMap.size());
	   
}

void P11Mapping::DelSlot(INDEX_SLOTID slotId) 
{
    map<INDEX_SLOTID ,slotIDServer>::iterator it;
    mutexSlotID.Lock();
    it= slotMap.find(slotId);
    if(it != slotMap.end()){
		LOGSERVERI(tag,"del slot %lu",slotId);
        slotMap.erase(it);
		statusMap[slotId] = CK_STATUS_ENUM_DEVICE_OFF;
    }
    mutexSlotID.Unlock();
}

int P11Mapping::GetSlotCount(){
	return slotMap.size();
}

void P11Mapping::DelSlot(string des) {
    map<CK_SLOT_ID,slotIDServer>::iterator it;
	INDEX_SLOTID temp = 0;
	
	mutexSlotID.Lock();
    for(it = slotMap.begin();it != slotMap.end();){
        if(it->second.des == des){
			temp = it->first;
			it = slotMap.erase(it);			
			statusMap[temp] = CK_STATUS_ENUM_DEVICE_OFF;
        }
		else{
			++it;
		}	
    }
	mutexSlotID.Unlock();
}

int P11Mapping::GetIndexByName(string des, INDEX_SLOTID *clientslotid){
	map<CK_SLOT_ID,slotIDServer>::iterator it;

	int ret = -1;
	
	mutexSlotID.Lock();
    for(it = slotMap.begin();it != slotMap.end();++it){
        if(it->second.des == des){
			*clientslotid = it->first;
			ret = 0;
			break;
        }
    }
	mutexSlotID.Unlock();
	return ret;
}	


int P11Mapping::GetSlot(INDEX_SLOTID clientslotid,slotIDServer *server)
{
    map<CK_SLOT_ID ,slotIDServer>::iterator it;

    mutexSlotID.Lock();
    it = slotMap.find(clientslotid);
    mutexSlotID.Unlock();
    if(it == slotMap.end()){
        LOGSERVERE(tag,"No slotid %ld",clientslotid);
        return CKR_SLOT_ID_INVALID;
    }
    if(NULL != server){
        *server = it->second;		
		LOGSERVERD(tag,"getslot: slotid %ld,server des = %s",clientslotid,server->des.data());
    }

    return CKR_OK;
}

INDEX_SLOTID P11Mapping::GetSlot(int index) {
    map<CK_SLOT_ID ,slotIDServer>::iterator it;
    mutexSlotID.Lock();
    it = slotMap.begin();

    if(index < slotMap.size()){
        for(int i = 0; i < index;i++){
            ++it;
        }
    }
    mutexSlotID.Unlock();
    return it->first;
}



void P11Mapping::SetSlotStatus(INDEX_SLOTID slotId, CK_STATUS_ENUM statusEnum) 
{
    map<CK_SLOT_ID,slotIDServer>::iterator it;

    it = slotMap.find(slotId);
    if(it != slotMap.end()){    
		LOGSERVERD(tag, "slot %lu status set to %d",slotId,statusEnum);
		statusMap[slotId] = statusEnum;
    }
	else
	{
		LOGSERVERD(tag, "slot %lu not found!",slotId);
	}
}

int P11Mapping::GetSlotStatus(INDEX_SLOTID slotId,CK_STATUS_ENUM_PTR statusEnum)
{	
	map<CK_SLOT_ID ,CK_STATUS_ENUM>::iterator it;
	it = statusMap.find(slotId);

	if(it != statusMap.end())
	{
		LOGSERVERD(tag,"find slot %lu, status is %d",slotId,*statusEnum);
		*statusEnum = it->second;
		return 0;
	}
	else
	{
		LOGSERVERE(tag,"slot %lu not found",slotId);
		*statusEnum = CK_STATUS_ENUM_DEVICE_ERROR;
	}

	return -1;
}


INDEX_SESSIONHANDLE P11Mapping::AddSession(INDEX_SLOTID slotId,sessionServer server)
{
	mutexSession.Lock();
	sessionMap.insert(make_pair(globeSessionIndex,server));
	
	ClientSessionAndSlotMap.insert(make_pair(globeSessionIndex,slotId));
	INDEX_SESSIONHANDLE temp = globeSessionIndex;
	globeSessionIndex++;
	
	mutexSession.Unlock();

	return temp;

}

int P11Mapping::GetSession(INDEX_SESSIONHANDLE clientsessionhandle,sessionServer *server)
{
    map<INDEX_SESSIONHANDLE,sessionServer>::iterator it;

    mutexSession.Lock();
    it = sessionMap.find(clientsessionhandle);
    if(it == sessionMap.end()){
        mutexSession.Unlock();
		LOGSERVERI(tag, "session 0x%lx not find",clientsessionhandle);
        return CKR_SESSION_HANDLE_INVALID;
    }

    mutexSession.Unlock();

    if(NULL != server){
        *server = it->second;
    }

    return CKR_OK;
}

int P11Mapping::GetSlotFromSession(INDEX_SESSIONHANDLE hsession, INDEX_SLOTID* pClient){
    map<INDEX_SESSIONHANDLE,INDEX_SLOTID>::iterator it;
    it = ClientSessionAndSlotMap.find(hsession);
    if(it == ClientSessionAndSlotMap.end()){
		LOGSERVERE(tag,"%lu, no session valid",hsession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if(pClient){
        *pClient = it->second;
    }

	return 0;
}

set<CK_SESSION_HANDLE> P11Mapping::ClearSessionbySlot(INDEX_SLOTID slotindex){
	map<INDEX_SESSIONHANDLE,INDEX_SLOTID>::iterator it;
	map<INDEX_SESSIONHANDLE,sessionServer>::iterator it_sessionmap;
	set<CK_SESSION_HANDLE> handles;
	handles.clear();

	for(it = ClientSessionAndSlotMap.begin();it != ClientSessionAndSlotMap.end();){
        if(it->second == slotindex){
			handles.insert(it->first);
			sessionMap.erase(it->first);	
			it = ClientSessionAndSlotMap.erase(it);	
        }
		else{
			++it;
		}
    }

	return handles;
}

