
#include <PEParser.h>

using namespace PEParser;

int main() {

	PEHANDLE l_peHandle = PEParser::OpenPEFile(L"C:\\Windows\\System32\\Notepad.exe");

	if (NULL != l_peHandle) {

		PEParser::getPEFileType(l_peHandle);
		PEParser::FreePEFile(l_peHandle);
	}
	return 0;
}