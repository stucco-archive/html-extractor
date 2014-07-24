

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import HTMLExtractor.BugtraqExtractor;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class BugtraqExtractorTest 
extends TestCase
{
	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public BugtraqExtractorTest( String testName )
	{
		super( testName );
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite()
	{
		return new TestSuite( BugtraqExtractorTest.class );
	}

	/**
	 * Tests conversion
	 */
	public void testConvert()
	{
		Charset charset = Charset.defaultCharset();
		int entryNum = 2222;
		boolean localMode = true;
		String filePath = "./testData/bugtraq/";
		String info, discussion, exploit, solution, references;
		
		try {
			//TODO could dry this out a bit...
			if(localMode){
				File infoFD = new File(filePath + entryNum + ".info.html");
				info = FileUtils.readFileToString(infoFD, charset);
				
				File discussionFD = new File(filePath + entryNum + ".discussion.html");
				discussion = FileUtils.readFileToString(discussionFD, charset);
				
				File exploitFD = new File(filePath + entryNum + ".exploit.html");
				exploit = FileUtils.readFileToString(exploitFD, charset);
				
				File solutionFD = new File(filePath + entryNum + ".solution.html");
				solution = FileUtils.readFileToString(solutionFD, charset);
				
				File referencesFD = new File(filePath + entryNum + ".references.html");
				references = FileUtils.readFileToString(referencesFD, charset);
			}
			else{
				URL u;
				u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/info");
				info = IOUtils.toString(u);
				
				u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/discussion");
				discussion = IOUtils.toString(u);
				
				u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/exploit");
				exploit = IOUtils.toString(u);
				
				u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/solution");
				solution = IOUtils.toString(u);
				
				u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/references");
				references = IOUtils.toString(u);
			}
			
			BugtraqExtractor bugtraqExt = new BugtraqExtractor(info, discussion, exploit, solution, references);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    assertTrue(verts.length() == 5);
		    
		    //TODO: should really search for this item, don't just assume it's location
		    JSONObject vuln = verts.getJSONObject( verts.length() - 1 );
		    verts.remove(verts.length() - 1);
		    
			//check the vuln node
		    //System.out.println(vuln.toString(2));
		    assertTrue( 0 == "vulnerability".compareTo(vuln.getString("vertexType")) );
	    	assertTrue( 0 == "Bugtraq".compareTo(vuln.getString("source")) );
	    	assertTrue( 0 == "vertex".compareTo(vuln.getString("_type")) );
	    	assertTrue( 0 == "Bugtraq_2222".compareTo(vuln.getString("_id")) );
	    	assertTrue( 0 == "Local".compareTo(vuln.getString("accessVector")) );
	    	assertTrue( 0 == "Design Error".compareTo(vuln.getString("class")) );
	    	assertTrue( 0 == "".compareTo(vuln.getString("CVE")) );
	    	//etc...
		    
		    //check the software vertices
		    int softwareCount = verts.length();
		    JSONObject sw;
		    String name, id;
		    for(int i=0; i< softwareCount; i++){
		    	sw = verts.optJSONObject(i);
		    	//System.out.println(sw);
		    	assertTrue( 0 == "software".compareTo(sw.getString("vertexType")) );
		    	assertTrue( 0 == "Bugtraq".compareTo(sw.getString("source")) );
		    	assertTrue( 0 == "vertex".compareTo(sw.getString("_type")) );
		    	name = sw.getString("name");
		    	id = sw.getString("_id");
		    	assertTrue( 0 == name.compareTo(id) );
		    }
		    
		    //check edges
		    //System.out.println(edges.toString(2));
		    int edgeCount = edges.length();
		    assertEquals(edgeCount, softwareCount);
		    JSONObject e;
		    String inV, outV;
		    for(int i=0; i< edgeCount; i++){
		    	e = edges.optJSONObject(i);
		    	//System.out.println(e);
		    	assertTrue( 0 == "hasVulnerability".compareTo(e.getString("_label")) );
		    	assertTrue( 0 == "Bugtraq".compareTo(e.getString("source")) );
		    	assertTrue( 0 == "edge".compareTo(e.getString("_type")) );
		    	assertTrue( 0 == "software".compareTo(e.getString("outVType")) );
		    	assertTrue( 0 == "vulnerability".compareTo(e.getString("inVType")) );
		    	inV = e.getString("_inV");
		    	outV = e.getString("_outV");
		    	id = e.getString("_id");
		    	assertTrue( 0 == id.compareTo(outV + "_to_" + inV) );
		    }
		    
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
		
	}

}
