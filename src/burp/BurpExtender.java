package burp;

import java.util.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
	IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("JSON JTree");
		callbacks.registerMessageEditorTabFactory(this);
		this.callbacks = callbacks;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new JsonJTree(callbacks);
	}
}
