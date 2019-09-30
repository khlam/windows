#Persistent
#SingleInstance, Force

return

OnClipboardChange:
if(Clipboard != ""){
	if !FileExist(Clipboard){
	    Clipboard = %Clipboard%
	}
}
; Has a problem with copy-pasting multiple files
