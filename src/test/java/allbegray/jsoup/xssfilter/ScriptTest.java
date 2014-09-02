package allbegray.jsoup.xssfilter;

import org.junit.Assert;
import org.junit.Test;

public class ScriptTest {

	@Test
	public void test1() {
		String dirty = "Site.com/search.php?search=<script>alert(\"XSS\");</script>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("Site.com/search.php?search="));
	}

	@Test
	public void test11() {
		String dirty = "http://example.com/index.php?user=<script>alert(123)</script>&p=123";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("http://example.com/index.php?user=&amp;p=123"));
	}

	@Test
	public void test113() {
		String dirty = "http://example.com/index.php?user=<script>window.onload = function() {var AllLinks=document.getElementsByTagName(\"a\"); AllLinks[0].href = \"http://badexample.com/malicious.exe\"; }</script> ";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("http://example.com/index.php?user="));
	}

	@Test
	public void test1131() {
		String dirty = "\" onfocus=\"alert(document.cookie)";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("&quot; onfocus=&quot;alert(document.cookie)"));
	}

	@Test
	public void test1131231() {
		String dirty = "\"%3cscript%3ealert(document.cookie)%3c/script%3e";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("&quot;%3cscript%3ealert(document.cookie)%3c/script%3e"));
	}

	@Test
	public void test2() {
		String dirty = "<script>alert('attack');</script>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

	@Test
	public void test3() {
		String dirty = "<SCRIPT SRC=http://evil-site.com/xss.js> </SCRIPT>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

	@Test
	public void test3123123() {
		String dirty = "<scr<script>ipt>alert(document.cookie)</script>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("ipt&gt;alert(document.cookie)"));
	}

	@Test
	public void test312312123123() {
		String dirty = "<SCRIPT%20a=\">\"%20SRC=\"http://attacker/xss.js\"></SCRIPT>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("&quot;%20SRC=&quot;http://attacker/xss.js&quot;&gt;"));
	}

	@Test
	public void test312312131232123123() {
		String dirty = "<script&param=>[...]</&param=script>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals("[...]"));
	}

	@Test
	public void test5() {
		String dirty = "<SCRIPT>x=/XSS/  alert(x.source)</SCRIPT>";
		String clean = XssFilter.getInstance().doFilter(dirty);
		System.out.println(clean);
		Assert.assertTrue(clean.equals(""));
	}

}
