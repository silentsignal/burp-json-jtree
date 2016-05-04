package burp;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.*;

import mjson.Json;

public class JsonJTree extends MouseAdapter implements IMessageEditorTab, ClipboardOwner
{
    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("(JSON root)");
	private final JTree tree = new JTree(root);
	private final DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
	private byte[] content;
	private final IExtensionHelpers helpers;
	private int bodyOffset;

	JsonJTree(IExtensionHelpers helpers) {
        tree.getSelectionModel().setSelectionMode
                (TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.addMouseListener(this);
		this.helpers = helpers;
	}

	@Override public void mousePressed (MouseEvent e) { if (e.isPopupTrigger()) doPop(e); }
	@Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) doPop(e); }

	private void doPop(MouseEvent e) {
		final JPopupMenu popup = new JPopupMenu();
		final TreePath sp = tree.getSelectionPath();
		if (sp == null) return; // nothing was selected
		final DefaultMutableTreeNode node = (DefaultMutableTreeNode)sp.getLastPathComponent();
		if (node == root) return; // disable for root
		final Node item = (Node)node.getUserObject();

		addToPopup(popup, "Copy key", new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				copyString(item.asKeyString());
			}
		});

		if (!item.isArrayOrObject()) {
			addToPopup(popup, "Copy value as string", new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					copyString(item.asValueString());
				}
			});
		}

		addToPopup(popup, "Copy value as JSON", new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				copyString(item.asJsonString());
			}
		});

		popup.show(e.getComponent(), e.getX(), e.getY());
	}

	private static void addToPopup(JPopupMenu pm, String title, ActionListener al) {
		final JMenuItem mi = new JMenuItem(title);
		mi.addActionListener(al);
		pm.add(mi);
	}

	private void copyString(final String value) {
		Toolkit.getDefaultToolkit().getSystemClipboard()
			.setContents(new StringSelection(value), this);
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

	private static class Node {
		private String key;
		private Json value;

		Node(String key, Json value) {
			this.key = key;
			this.value = value;
		}

		public boolean isArrayOrObject() {
			return value.isArray() || value.isObject();
		}

		public String asValueString() { return value.asString(); }
		public String asJsonString()  { return value.toString(); }
		public String asKeyString()   { return key; }

		@Override
		public String toString() {
			if (value.isNull()) {
				return key + ": null";
			} else if (value.isString()) {
				return key + ": \"" + value.asString() + '"';
			} else if (value.isNumber() || value.isBoolean()) {
				return key + ": " + value.toString();
			}
			return key;
		}
	}

	private void dumpObjectNode(DefaultMutableTreeNode dst, Json src) {
		Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
		tm.putAll(src.asJsonMap());
		for (Map.Entry<String, Json> e : tm.entrySet()) {
			processNode(dst, e.getKey(), e.getValue());
		}
	}

	private void dumpArrayNode(DefaultMutableTreeNode dst, Json src) {
		int i = 0;
		for (Json value : src.asJsonList()) {
			String key = '[' + String.valueOf(i++) + ']';
			processNode(dst, key, value);
		}
	}

	private void processNode(DefaultMutableTreeNode dst, String key, Json value) {
		final DefaultMutableTreeNode node =
			new DefaultMutableTreeNode(new Node(key, value));
		dst.add(node);
		if (value.isObject()) {
			dumpObjectNode(node, value);
		} else if (value.isArray()) {
			dumpArrayNode(node, value);
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
	public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
