package allbegray.jsoup.xssfilter;

import org.junit.Assert;
import org.junit.Test;

public class EtcTest {

	@Test
	public void test4() {
		String dirty = "<iframe src=http://evil-site.com/evil.html ";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

	@Test
	public void test6() {
		String dirty = "<BODY BACKGROUND=\"javascript:alert('XSS')\"> ";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

	@Test
	public void test7() {
		String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

	@Test
	public void test8() {
		String dirty = "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}
	
	@Test
	public void test81() {
		String dirty = "<b onmouseover=alert('Wufff!')>click me!</b>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("<b>click me!</b>"));
	}
	
	@Test
	public void test811() {
		String dirty = "<form>폼안에 있는 내용은 어떻게 되나요?</form>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("폼안에 있는 내용은 어떻게 되나요?"));
	}

}
