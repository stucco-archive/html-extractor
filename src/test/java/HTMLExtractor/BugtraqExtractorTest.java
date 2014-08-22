package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit test for simple App.
 */
public class BugtraqExtractorTest {
	
	private Map<String,String> loadContent(int entryNum, boolean localMode) throws IOException{
		Map<String,String> pageContent = new HashMap<String,String>();
		String filePath = "./testData/bugtraq/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryNum + ".info.html");
			String info = FileUtils.readFileToString(infoFD, charset);
			pageContent.put("info", info);
			
			File discussionFD = new File(filePath + entryNum + ".discussion.html");
			String discussion = FileUtils.readFileToString(discussionFD, charset);
			pageContent.put("discussion", discussion);
			
			File exploitFD = new File(filePath + entryNum + ".exploit.html");
			String exploit = FileUtils.readFileToString(exploitFD, charset);
			pageContent.put("exploit", exploit);
			
			File solutionFD = new File(filePath + entryNum + ".solution.html");
			String solution = FileUtils.readFileToString(solutionFD, charset);
			pageContent.put("solution", solution);
			
			File referencesFD = new File(filePath + entryNum + ".references.html");
			String references = FileUtils.readFileToString(referencesFD, charset);
			pageContent.put("references", references);
		}
		else{
			URL u;
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/info");
			pageContent.put("info", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/discussion");
			pageContent.put("discussion", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/exploit");
			pageContent.put("exploit", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/solution");
			pageContent.put("solution", IOUtils.toString(u));
			
			u = new URL("http://www.securityfocus.com/bid/"+entryNum+"/references");
			pageContent.put("references", IOUtils.toString(u));
		}
		return pageContent;
	}
	
	/**
	 * Tests conversion
	 */
	@Test
	public void testConvert()
	{
		int entryNum = 2222;
		boolean localMode = true;
		String info, discussion, exploit, solution, references;
		
		try {
			Map<String,String> pageContent = loadContent(entryNum, localMode);
			info = pageContent.get("info");
			discussion = pageContent.get("discussion");
			exploit = pageContent.get("exploit");
			solution = pageContent.get("solution");
			references = pageContent.get("references");
			
			//TODO maybe add a BugtraqExtractor(Map)?
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
	@Test
	public void testPlaceholder()
	{
		
	}

}
