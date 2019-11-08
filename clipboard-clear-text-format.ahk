#Persistent
#SingleInstance, Force

return

OnClipboardChange:
if(Clipboard != ""){
	If !(WinActive("ahk_class CabinetWClass") or WinActive("ahk_class Progman")) {
	    Clipboard = %Clipboard%
	}
}
