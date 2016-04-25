package burp;

import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.*;

import mjson.Json;

public class JsonJTree implements IMessageEditorTab
{
    private DefaultMutableTreeNode root = new DefaultMutableTreeNode("(JSON root)");
	private JTree tree = new JTree(root);
	private DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
	private byte[] content;
	private IExtensionHelpers helpers;
	private int bodyOffset;

	JsonJTree(IExtensionHelpers helpers) {
        tree.getSelectionModel().setSelectionMode
                (TreeSelectionModel.SINGLE_TREE_SELECTION);
		this.helpers = helpers;
	}

	public boolean isEnabled(byte[] content, boolean isRequest) {
		int len = content.length;
		if (len == 0) {
			root.removeAllChildren();
			model.reload(root);
			return false;
		}
		if (isRequest) {
			IRequestInfo i = helpers.analyzeRequest(content);
			bodyOffset = i.getBodyOffset();
		} else {
			IResponseInfo i = helpers.analyzeResponse(content);
			bodyOffset = i.getBodyOffset();
		}
		return (len - bodyOffset >= 2) &&
			content[bodyOffset] == (byte)'{' && content[len - 1] == (byte)'}';
		// TODO try parsing at this stage
	}

	public void setMessage(byte[] content, boolean isRequest) {
		this.content = content;
		root.removeAllChildren();
		if (content != null) {
			Json node = Json.read(new String(content, bodyOffset,
						content.length - bodyOffset, StandardCharsets.UTF_8));
			// TODO UTF-8?
			dumpObjectNode(root, node);
		}
		model.reload(root);
		expandAllNodes(tree, 0, tree.getRowCount());
	}

	private void dumpObjectNode(DefaultMutableTreeNode dst, Json src) {
		Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
		tm.putAll(src.asJsonMap());
		for (Map.Entry<String, Json> e : tm.entrySet()) {
			String caption = e.getKey();
			Json value = e.getValue();
			if (value.isNull()) {
				caption += ": null";
			} else if (value.isString()) {
				caption += ": \"" + value.asString() + '"';
			} else if (value.isNumber() || value.isBoolean()) {
				caption += ": " + value.asString();
			}
			DefaultMutableTreeNode node = new DefaultMutableTreeNode(caption);
			dst.add(node);
			if (value.isObject()) {
				dumpObjectNode(node, value);
			} else if (value.isArray()) {
				dumpArrayNode(node, value);
			}
		}
	}

	private void dumpArrayNode(DefaultMutableTreeNode dst, Json src) {
		int i = 0;
		for (Json value : src.asJsonList()) {
			String caption = '[' + String.valueOf(i++) + ']';
			if (value.isNull()) {
				caption = "null";
			} else if (value.isString()) {
				caption = '"' + value.asString() + '"';
			} else if (value.isNumber() || value.isBoolean()) {
				caption = value.asString();
			}
			DefaultMutableTreeNode node = new DefaultMutableTreeNode(caption);
			dst.add(node);
			if (value.isObject()) {
				dumpObjectNode(node, value);
			} else if (value.isArray()) {
				dumpArrayNode(node, value);
			}
		}
	}

	private void expandAllNodes(JTree tree, int startingIndex, int rowCount){
		for(int i=startingIndex;i<rowCount;++i){
			tree.expandRow(i);
		}

		if(tree.getRowCount()!=rowCount){
			expandAllNodes(tree, rowCount, tree.getRowCount());
		}
	}

	public String getTabCaption() { return "JSON JTree"; }
	public Component getUiComponent() { return new JScrollPane(tree); }
	public byte[] getMessage() { return content; }
	public boolean isModified() { return false; }
	public byte[] getSelectedData() { return null; }
}
