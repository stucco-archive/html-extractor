

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import HTMLExtractor.FSecureExtractor;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class FSecureExtractorTest 
extends TestCase
{
	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public FSecureExtractorTest( String testName )
	{
		super( testName );
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite()
	{
		return new TestSuite( FSecureExtractorTest.class );
	}

	private String loadContent(String entryName, boolean localMode) throws IOException{
		String pageContent;
		String filePath = "./testData/f-secure/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryName + ".shtml");
			pageContent = FileUtils.readFileToString(infoFD, charset);
		}
		else{
			URL u;
			u = new URL("http://www.f-secure.com/v-descs/"+entryName+".shtml");
			pageContent = IOUtils.toString(u);
		}
		return pageContent;
	}
	
	/**
	 * Tests conversion
	 */
	public void testConvert()
	{
		String entryName = "application_w32_installbrain";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		  //TODO...asserts
		  
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test stub
	 */
	public void testPlaceholder()
	{
		String entryName = "backdoor_w32_havex";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    //TODO...asserts
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test stub
	 */
	public void testPlaceholder2()
	{
		String entryName = "trojan_html_browlock";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    //TODO...asserts
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

}
