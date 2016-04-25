package burp;

import java.util.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
	IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("JSON JTree");
		callbacks.registerMessageEditorTabFactory(this);
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new JsonJTree(helpers);
	}
}
