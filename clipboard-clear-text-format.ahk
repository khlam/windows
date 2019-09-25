#Persistent
#SingleInstance, Force

return

OnClipboardChange:
if(Clipboard != ""){
	if !FileExist(Clipboard){
	    Clipboard = %Clipboard%
	}
}
