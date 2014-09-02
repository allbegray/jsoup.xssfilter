package allbegray.jsoup.xssfilter.config;

import java.io.InputStream;

import org.jsoup.safety.Whitelist;

import allbegray.jsoup.xssfilter.markup.Attribute;
import allbegray.jsoup.xssfilter.markup.AttributeGroup;
import allbegray.jsoup.xssfilter.markup.Tag;
import allbegray.jsoup.xssfilter.markup.WhitelistRule;
import allbegray.jsoup.xssfilter.markup.parse.MarkupParser;

import com.thoughtworks.xstream.XStream;

public class XssConfiguration {

	public static Whitelist newInstance(String file) {

		InputStream is = null;
		try {
			is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);

			XStream xStream = new XStream();
			xStream.aliasType("whitelistRule", WhitelistRule.class);

			xStream.aliasType("attrGroup", AttributeGroup.class);
			xStream.aliasAttribute(AttributeGroup.class, "name", "name");
			xStream.addImplicitCollection(AttributeGroup.class, "attributes", "attr", String.class);

			xStream.aliasType("tag", Tag.class);
			xStream.aliasAttribute(Tag.class, "name", "name");
			xStream.aliasAttribute(Tag.class, "disabled", "disabled");
			xStream.addImplicitCollection(Tag.class, "attributes", "attr", Attribute.class);

			xStream.aliasType("attribute", Attribute.class);
			xStream.aliasAttribute(Attribute.class, "name", "name");
			xStream.aliasAttribute(Attribute.class, "enforced", "enforced");
			xStream.addImplicitCollection(Attribute.class, "protocols", "protocol", String.class);

			WhitelistRule whitelistRule = (WhitelistRule) xStream.fromXML(is);

			return new MarkupParser().parser(whitelistRule);

		} catch (Exception e) {
			throw new RuntimeException(String.format("Cannot parse the configuration file [%s].", file), e);
		} finally {
			if (is != null) try { is.close(); } catch(Exception e) {}
		}

	}

}
