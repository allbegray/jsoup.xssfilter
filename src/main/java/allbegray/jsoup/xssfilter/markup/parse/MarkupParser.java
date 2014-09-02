package allbegray.jsoup.xssfilter.markup.parse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jsoup.safety.Whitelist;

import allbegray.jsoup.xssfilter.markup.Attribute;
import allbegray.jsoup.xssfilter.markup.AttributeGroup;
import allbegray.jsoup.xssfilter.markup.Tag;
import allbegray.jsoup.xssfilter.markup.WhitelistRule;

public class MarkupParser {

	private Whitelist whitelist = null;

	public MarkupParser() {
		whitelist = new Whitelist();
	}

	public Whitelist parser(WhitelistRule whitelistRule) {

		List<AttributeGroup> list = whitelistRule.getAttributeGroups();
		Map<String, List<String>> attributeGroupMap = new HashMap<String, List<String>>(list.size());
		for (AttributeGroup group : list) {
			attributeGroupMap.put(group.getName(), group.getAttributes());
		}

		for (Tag tag : whitelistRule.getTags()) {
			if ("true".equalsIgnoreCase(tag.getDisabled())) {
				continue;
			}

			List<Attribute> attributes = tag.getAttributes();
			for (Attribute attr : attributes) {
				String attrName = attr.getName();
				if (Character.isUpperCase(attrName.charAt(0)) == true) {
					List<String> attributeGroup = attributeGroupMap.get(attrName);
					for (String attrGroup : attributeGroup) {
						addWhitelist(tag.getName(), attrGroup, attr.getEnforced(), attr.getProtocols());
					}
				} else {
					addWhitelist(tag.getName(), attrName, attr.getEnforced(), attr.getProtocols());
				}
			}
		}

		return whitelist;
	}

	private void addWhitelist(String tagName, String attrName, String enforced, List<String> protocols) {
		whitelist.addAttributes(tagName, attrName);
		if (enforced != null && !"".equals(enforced)) {
			whitelist.addEnforcedAttribute(tagName, attrName, enforced);
		}
		if (protocols.size() > 0) {
			whitelist.addProtocols(tagName, attrName, protocols.toArray(new String[protocols.size()]));
		}
	}

}
