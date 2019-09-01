#Persistent
#SingleInstance, Force

return

OnClipboardChange:
if(Clipboard != "")
    Clipboard = %Clipboard%
