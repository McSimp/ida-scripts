// vtable_to_struct.idc
// Converts a VTable to a struct
// Based on VTableRec.idc by Sirmabus and modified by BAILOPAN

#include <idc.idc>

static CleanupName(name)
{
	auto i;
	auto current;
	for(i = 0; i < strlen(name); i++)
	{
		current = name[i];
		if(current == ":" || current == "~")
		{
			name[i] = "_";
		}
	}

	return name;
}

static main()
{
	auto pAddress, iIndex;
	auto skipAmt;
	auto structName;
	auto structID;

	SetStatus(IDA_STATUS_WORK);

	// User selected vtable block
	pAddress = ScreenEA();
	
	if (pAddress == BADADDR)
	{	   
		Message("** No vtable selected! Aborted **");
		Warning("No vtable selected!\nSelect vtable block first.");													 
		SetStatus(IDA_STATUS_READY);
		return;
	}

	SetStatus(IDA_STATUS_WAITING);
	
	// Ask for settings
	skipAmt = AskLong(0, "Number of vtable entries to ignore for indexing:");
	structName = AskStr("CClass_vtable", "Enter the name of the vtable struct:");
	
	SetStatus(IDA_STATUS_WORK);
	
	// If the vtable struct already exists, delete it
	structID = GetStrucIdByName(structName);
	if (structID != -1)
	{
		Message("Deleted old vtable struct\n");
		DelStruc(structID);
	}
	
	// Create the struct to import vtable names into
	structID = AddStruc(-1, structName);
	
	auto szFuncName, szFullName, szCleanName;

	// For linux, skip the first entry
	if (Dword(pAddress) == 0)
	{
		pAddress = pAddress + 8;
	}
	
	pAddress = pAddress + (skipAmt * 4);

	// Loop through the vtable block
	while (pAddress != BADADDR)
	{
		auto real_addr;
		real_addr = Dword(pAddress);
		
		szFuncName = GetFunctionName(real_addr);
		if (strlen(szFuncName) == 0)
		{
			break;
		}
		
		szFullName = Demangle(szFuncName, INF_SHORT_DN);
		if (szFullName == "")
		{
			szFullName = szFuncName;
		}
		
		if (strstr(szFullName, "_ZN") != -1)
		{
			Warning("You must toggle GCC v3.x demangled names!\n");
			DelStruc(structID);
			break;
		}

		szCleanName = CleanupName(szFullName);

		while (AddStrucMember(structID, szCleanName, iIndex * 4, 0x20000400, -1, 4) == STRUC_ERROR_MEMBER_NAME)
		{
			szCleanName = szCleanName + "_";
		};

		pAddress = pAddress + 4;
		iIndex++;
	};

	Message("Successfully added %d vtable entries to struct %s.\n", iIndex, structName);

	Message("\nDone.\n\n");
	SetStatus(IDA_STATUS_READY);
}