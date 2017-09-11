
#include <PEParser.h>

using namespace PEParser;

int main() {

	PEHANDLE l_peHandle = PEParser::OpenFile(L"C:\\Windows\\System32\\notepad.exe");

	if (NULL != l_peHandle) {

		PEParser::getPEFileType(l_peHandle);
		PEParser::CloseFile(l_peHandle);
	}
	return 0;
}