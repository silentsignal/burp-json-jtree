package burp;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import java.util.regex.*;

import javax.swing.*;
import javax.swing.tree.*;

import mjson.Json;

public class JsonJTree extends MouseAdapter implements IMessageEditorTab, ClipboardOwner
{
	private final JPanel panel = new JPanel(new BorderLayout());
    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode();
	private final JTree tree = new JTree(root);
	private final JComboBox<Part> comboBox = new JComboBox<>();
	private final DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
	private byte[] content;
	private final IExtensionHelpers helpers;
	private final IBurpExtenderCallbacks callbacks;
	private static final Pattern JWT_RE = Pattern.compile(
			"(?:[-_A-Z0-9]+\\.){2}[-_A-Z0-9]+", Pattern.CASE_INSENSITIVE);

	JsonJTree(IBurpExtenderCallbacks callbacks) {
        tree.getSelectionModel().setSelectionMode
                (TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.addMouseListener(this);
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		comboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				root.removeAllChildren();
				Part part = comboBox.getItemAt(comboBox.getSelectedIndex());
				Json node = Json.read(part.decode());
				root.setUserObject(new Node(null, node));
				if (node.isObject()) {
					dumpObjectNode(root, node);
				} else if (node.isArray()) {
					dumpArrayNode(root, node);
				}
				model.reload(root);
				expandAllNodes(tree, 0, tree.getRowCount());
			}
		});
		panel.add(comboBox, BorderLayout.NORTH);
		panel.add(new JScrollPane(tree), BorderLayout.CENTER);
	}

	@Override public void mousePressed (MouseEvent e) { if (e.isPopupTrigger()) doPop(e); }
	@Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) doPop(e); }

	private void doPop(MouseEvent e) {
		final JPopupMenu popup = new JPopupMenu();
		final TreePath sp = tree.getSelectionPath();
		if (sp == null) return; // nothing was selected
		final DefaultMutableTreeNode node = (DefaultMutableTreeNode)sp.getLastPathComponent();
		final Node item = (Node)node.getUserObject();

		if (node != root) {
			addToPopup(popup, "Copy key", new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					copyString(item.asKeyString());
				}
			});
		}

		if (!item.isArrayOrObject()) {
			final String value = item.asValueString();

			addToPopup(popup, "Copy value as string", new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					copyString(value);
				}
			});

			if (mayBeJwt(value)) {
				addToPopup(popup, "Convert JWT to EsPReSSO format", new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						convertJwt(value);
					}
				});
			}
		}

		addToPopup(popup, "Copy value as JSON", new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				copyString(item.asJsonString());
			}
		});


		popup.show(e.getComponent(), e.getX(), e.getY());
	}

	private static boolean mayBeJwt(final String value) {
		return JWT_RE.matcher(value).matches();
	}

	private void convertJwt(final String jwt) {
		final java.util.List<String> headers = Arrays.asList(
				"GET / HTTP/1.0",
				"Content-Type: application/x-www-form-urlencoded",
				"X-Message: dummy request, do not send!");
		final byte[] body = helpers.stringToBytes("access_token=" + jwt);
		final byte[] request = helpers.buildHttpMessage(headers, body);
		callbacks.sendToRepeater("example.com", 80, false, request, "JWT");
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
		if (content.length == 0) {
			root.removeAllChildren();
			model.reload(root);
			return false;
		}
		return !parse(content, isRequest).isEmpty();
		// TODO try parsing at this stage
	}

	private final static byte[] BOM_UTF8 = {(byte)0xEF, (byte)0xBB, (byte)0xBF};
	private final static int MIN_LEN = 2;

	private void detectRawJson(Vector<Part> dest, byte[] content, int bodyOffset,
			IRequestInfo req) {
		final int len = content.length;
		final int bodyLen = len - bodyOffset;
		if (bodyLen < MIN_LEN) return;
		byte[] firstThreeBytes = Arrays.copyOfRange(content,
				bodyOffset, bodyOffset + BOM_UTF8.length);
		if (Arrays.equals(firstThreeBytes, BOM_UTF8) &&
				bodyLen > BOM_UTF8.length + MIN_LEN) bodyOffset += BOM_UTF8.length;
		addIfJson(dest, bytesToString(Arrays.copyOfRange(content, bodyOffset, len)), null);
	}

	private final CharsetDecoder utfDecoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(
			CodingErrorAction.REPORT);

	private String bytesToString(byte[] source) {
		try {
			return utfDecoder.decode(ByteBuffer.wrap(source)).toString();
		} catch (CharacterCodingException e) {
			return helpers.bytesToString(source);
		}
	}

	private void detectParamJson(Vector<Part> dest, byte[] content, int bodyOffset,
			IRequestInfo req) {
		if (req == null) return;
		java.util.List<IParameter> params = req.getParameters();
		ArrayList<Part> parts = new ArrayList<>(params.size());
		for (IParameter param : params) {
			String value = param.getValue();
			java.util.List<String> candidates = new ArrayList<String>(
					Arrays.asList(value, helpers.urlDecode(value)));
			for (final String s : candidates) {
				addIfJson(dest, s, param);
			}
		}
	}

	public interface Part {
		public String decode();
	}

	private static void addIfJson(Vector<Part> dest, String value, IParameter param) {
		if (mightBeJson(value)) {
			dest.add(new Part() {
				public String decode() { return value; }

				@Override
				public String toString() {
					if (param == null) return "HTTP body";
					return parameterTypeToString(param.getType()) +
						" \"" + param.getName() + '"';
				}
			});
		}
	}

	private static boolean mightBeJson(final String value) {
		final int len = value.length();
		if (len < MIN_LEN) return false;
		final char firstChar = value.charAt(0);
		return
			((firstChar | (byte)0x20) == (byte)0x7b) && // '[' = 0x5b, '{' = 0x7b, former missing bit 0x20
			(value.charAt(len - 1) == firstChar + 2);   // ']' = 0x5d, '}' = 0x7d, offset is 2 for both
	}

	private static String parameterTypeToString(final byte type) {
		switch (type) {
			case IParameter.PARAM_URL: return "URL parameter";
			case IParameter.PARAM_BODY: return "Body parameter";
			case IParameter.PARAM_COOKIE: return "HTTP cookie";
			case IParameter.PARAM_XML: return "XML element";
			case IParameter.PARAM_XML_ATTR: return "XML attribute";
			case IParameter.PARAM_MULTIPART_ATTR: return "MIME multipart attribute";
			case IParameter.PARAM_JSON: return "JSON item";
			default: return "Unknown parameter";
		}
	}

	private Vector<Part> parse(byte[] content, boolean isRequest) {
		IRequestInfo req = null;
		int bodyOffset;
		if (isRequest) {
			req = helpers.analyzeRequest(content);
			bodyOffset = req.getBodyOffset();
		} else {
			IResponseInfo i = helpers.analyzeResponse(content);
			bodyOffset = i.getBodyOffset();
		}
		Vector<Part> parts = new Vector<>();
		detectRawJson(parts, content, bodyOffset, req);
		detectParamJson(parts, content, bodyOffset, req);
		return parts;
	}

	public void setMessage(byte[] content, boolean isRequest) {
		this.content = content;
		root.removeAllChildren();
		if (content != null) {
			Vector<Part> parts = parse(content, isRequest);
			if (parts.size() == 1) {
				Json node = Json.read(parts.get(0).decode());
				root.setUserObject(new Node(null, node));
				if (node.isObject()) {
					dumpObjectNode(root, node);
				} else if (node.isArray()) {
					dumpArrayNode(root, node);
				}
				comboBox.setVisible(false);
			} else {
				comboBox.setModel(new DefaultComboBoxModel<>(parts));
				comboBox.setSelectedIndex(0);
				comboBox.setVisible(true);
			}
		} else {
			root.setUserObject(new Node(null, null));
		}
		model.reload(root);
		expandAllNodes(tree, 0, tree.getRowCount());
	}

	private static class Node {
		private final String key;
		private final Json value;

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
			if (key == null) return "(JSON root)";
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

	private static void dumpObjectNode(DefaultMutableTreeNode dst, Json src) {
		Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
		tm.putAll(src.asJsonMap());
		for (Map.Entry<String, Json> e : tm.entrySet()) {
			processNode(dst, e.getKey(), e.getValue());
		}
	}

	private static void dumpArrayNode(DefaultMutableTreeNode dst, Json src) {
		int i = 0;
		for (Json value : src.asJsonList()) {
			String key = '[' + String.valueOf(i++) + ']';
			processNode(dst, key, value);
		}
	}

	private static void processNode(DefaultMutableTreeNode dst, String key, Json value) {
		final DefaultMutableTreeNode node =
			new DefaultMutableTreeNode(new Node(key, value));
		dst.add(node);
		// check if `value` is actually JSON serialized data "embedded" as string
		if (value.isString()) {
			// if so, deserialize and treat the result as first-class content
			final String stringValue = value.asString();
			if (mightBeJson(stringValue)) {
				try {
					value = Json.read(stringValue);
				} catch (Exception e) {
					// ignore false positive
				}
			}
		}
		if (value.isObject()) {
			dumpObjectNode(node, value);
		} else if (value.isArray()) {
			dumpArrayNode(node, value);
		}
	}

	private static void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
		for (int i = startingIndex; i < rowCount; i++) {
			tree.expandRow(i);
		}

		if (tree.getRowCount() != rowCount) {
			expandAllNodes(tree, rowCount, tree.getRowCount());
		}
	}

	public String getTabCaption() { return "JSON JTree"; }
	public Component getUiComponent() { return panel; }
	public byte[] getMessage() { return content; }
	public boolean isModified() { return false; }
	public byte[] getSelectedData() { return null; }
	public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
