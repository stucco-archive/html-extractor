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

import HTMLExtractor.SophosExtractor;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for Sophos extractor.
 */
public class SophosExtractorTest{
	
	private Map<String,String> loadContent(String entryName, boolean localMode) throws IOException{
		Map<String,String> pageContent = new HashMap<String,String>();
		String filePath = "./testData/sophos/";
		Charset charset = Charset.defaultCharset();
		if(localMode){
			File infoFD = new File(filePath + entryName + ".aspx");
			String info = FileUtils.readFileToString(infoFD, charset);
			pageContent.put("summary", info);
			
			File discussionFD = new File(filePath + entryName + "_details.aspx");
			String discussion = FileUtils.readFileToString(discussionFD, charset);
			pageContent.put("details", discussion);
		}
		else{
			URL u;
			u = new URL("http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/"+entryName+".aspx");
			pageContent.put("summary", IOUtils.toString(u));
			
			u = new URL("http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/"+entryName+"/detailed-analysis.aspx");
			pageContent.put("details", IOUtils.toString(u));
		}
		return pageContent;
	}
	
	/**
	 * Test with "Mal~Conficker-A" sample data
	 */
	@Test
	public void test_Mal_Conficker_A()
	{
		String entryName = "Mal~Conficker-A";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'malwareType': ['Malicious behavior'],"+
			    	  "  'signatureDate': 1227708812000,"+
			    	  "  'source': 'Sophos',"+
			    	  "  '_id': 'Mal/Conficker-A',"+
			    	  "  'prevalence': 'Major Outbreak',"+
			    	  "  'name': 'Mal/Conficker-A',"+
			    	  "  'discoveryDate': 1227708812000,"+
			    	  "  'aliases': [ "+
			    	  "    'Mal/Conficker-A', "+
			    	  "    'Net-Worm.Win32.Kido', "+
			    	  "    'W32/Conficker.worm', "+
			    	  "    'WORM_DOWNAD.AD',"+
			    	  "    'Worm:W32/Downadup',"+
			    	  "    'Worm:Win32/Conficker.gen!A'],"+
			    	  "  'modifiedDate': 1319777485000,"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Test with "Troj~FBJack-A" sample data
	 */
	@Test
	public void test_Troj_FBJack_A()
	{
		String entryName = "Troj~FBJack-A";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  'signatureDate': 1284593193000,"+
			    	  "  'source': 'Sophos',"+
			    	  "  '_id': 'Troj/FBJack-A',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'name': 'Troj/FBJack-A',"+
			    	  "  'knownFileTypes': ['application/octet-stream','text/html'],"+
			    	  "  'discoveryDate': 1284593193000,"+
			    	  "  'modifiedDate': 1284624938000,"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~JsRedir-NN" sample data
	 */
	@Test
	public void test_Troj_JsRedir_NN()
	{
		String entryName = "Troj~JsRedir-NN";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'md5Hashes': ["+
			    	  "    '257d848787712c79e5871d36efe6ca31',"+
			    	  "    '44007d95ffcbe791e22f594638f55651',"+
			    	  "    'f53c86f176e97c86fc0b363851b53a12'],"+
			    	  "  'aliases': [ "+
			    	  "    'Troj/JsRedir-NN',"+
			    	  "    'Trojan.JS.Blacole.Gen'], "+
			    	  "  'sha1Hashes': ["+
			    	  "    '00065de02b0b5f8dba43148b074b880508aac368',"+
			    	  "    '000862ed10c9f85bae2c17fd7acf8bc4d23b0f5b',"+
			    	  "    '00089d33d7d5b8260481c3269a896733aa5cf483'],"+
			    	  "  'modifiedDate': 1403616042000,"+
			    	  "  '_type': 'vertex',"+
			    	  "  'signatureDate': 1394816824000,"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  '_id': 'Troj/JsRedir-NN',"+
			    	  "  'source': 'Sophos',"+
			    	  "  'name': 'Troj/JsRedir-NN',"+
			    	  "  'knownFileTypes': ['JavaScript','application/octet-stream','text/cpp'],"+
			    	  "  'discoveryDate': 1189310400000,"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Agent-DP" sample data
	 * (This entry is almost entirely free text, so not much to build here.)
	 */
	@Test
	public void test_Troj_Agent_DP()
	{
		String entryName = "Troj~Agent-DP";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  'source': 'Sophos',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  '_id': 'Troj/Agent-DP',"+
			    	  "  'name': 'Troj/Agent-DP'"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Zbot-ITY" sample data
	 * (Dynamic analysis of this one gives lots of complicated results.)
	 */
	@Test
	public void test_Troj_Zbot_ITY()
	{
		String entryName = "Troj~Zbot-ITY";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'aliases': [ "+
			    	  "    'Gen:Variant.Graftor.150885',"+
			    	  "    'Troj/Zbot-ITY'], "+
			    	  "  'md5Hashes': ["+
			    	  "    '599990d8fa3d211b0b775d82dd939526',"+
			    	  "    'ca2fe00295a6255ced2778fb9f43146f'],"+
			    	  "  'sha1Hashes': ["+
			    	  "    '8bff3c73c92314a7d094a0d024cf57a722b0b198',"+
			    	  "    '9017bd0da5f94f4ba899e5d990c8c4f4792d6876'],"+
			    	  "  'filesCreated': ["+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\Application Data\\\\Poce\\\\anyn.ezo',"+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\Application Data\\\\Veufno\\\\buerx.exe'],"+
			    	  "  'filesModified': ["+
			    	  "    '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Folders.dbx',"+
			    	  "    '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Inbox.dbx',"+
			    	  "    '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Offline.dbx'],"+
			    	  "  'processesCreated': ["+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\application data\\\\veufno\\\\buerx.exe',"+
			    	  "    'c:\\\\windows\\\\system32\\\\cmd.exe',"+
			    	  "    'c:\\\\windows\\\\system32\\\\hostname.exe',"+
			    	  "    'c:\\\\windows\\\\system32\\\\ipconfig.exe',"+
			    	  "    'c:\\\\windows\\\\system32\\\\tasklist.exe'],"+
			    	  "  'registryKeysCreated': ["+
                      "    'HKCU\\\\Identities',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Dyxol',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Internet Explorer\\\\Privacy',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'],"+
                      "  'registryKeysModified': ["+
                      "    'HKCU\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Software\\\\Microsoft\\\\Outlook Express\\\\5.0',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\0',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\1',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\2',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\4',"+
                      "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UnreadMail\\\\user@example.com'],"+
			    	  "  'urlsUsed': ["+
                      "    'http://www.google.com/webhp',"+
                      "    'http://www.google.ie/webhp'],"+
	                  "  'dnsRequests': ["+
                      "    'franciz-industries.biz',"+
                      "    'www.google.com',"+
                      "    'www.google.ie'],"+
			    	  "  '_type': 'vertex',"+
			    	  "  'modifiedDate': 1408162427000,"+
			    	  "  'signatureDate': 1408162427000,"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  '_id': 'Troj/Zbot-ITY',"+
			    	  "  'source': 'Sophos',"+
			    	  "  'name': 'Troj/Zbot-ITY',"+
			    	  "  'knownFileTypes': ['Windows executable'],"+
			    	  "  'discoveryDate': 1407902400000"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Zbot-AAA" sample data
	 * (Similar to above, but with less detailed results.)
	 */
	@Test
	public void test_Troj_Zbot_AAA()
	{
		String entryName = "Troj~Zbot-AAA";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'aliases': [ "+
			    	  "    'TR/Spy.ZBot.aput',"+
			    	  "    'Troj/Zbot-AAA',"+
			    	  "    'Trojan-Spy.Win32.Zbot.aput'], "+
			    	  "  'md5Hashes': ["+
			    	  "    '15eabc798ddf5542afec25946a00e987',"+
			    	  "    'c4e28e07ebb3a69fd165977f0331f1c5',"+
			    	  "    'd9dfa48afeb08f6e67fb8b2254a76870'],"+
			    	  "  'sha1Hashes': ["+
			    	  "    '5d012753322151c9d24bf45b98c35336225f383f',"+
			    	  "    'b1005a9483866a45046a9b9d9bea09d39b29dcde',"+
			    	  "    'b76ad9b1c6e01e41b8e05ab9be0617fff06fad98'],"+
			    	  "  'filesCreated': ["+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\Application Data\\\\Neceq\\\\esbo.exe'],"+
			    	  "  'processesCreated': ["+
			    	  "    'c:\\\\windows\\\\system32\\\\cmd.exe'],"+
			    	  "  '_type': 'vertex',"+
			    	  "  'modifiedDate': 1286016118000,"+
			    	  "  'signatureDate': 1286016118000,"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  '_id': 'Troj/Zbot-AAA',"+
			    	  "  'source': 'Sophos',"+
			    	  "  'name': 'Troj/Zbot-AAA',"+
			    	  "  'knownFileTypes': ['application/x-ms-dos-executable'],"+
			    	  "  'discoveryDate': 1285732800000"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Test with "Troj~Weelsof-FG" sample data
	 * (Similar structure, only one sample shown, somewhat different fields included/excluded)
	 */
	@Test
	public void test_Troj_Weelsof_FG()
	{
		String entryName = "Troj~Weelsof-FG";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'aliases': [ "+
			    	  "    'TR/Crypt.XPACK.Gen7',"+
			    	  "    'Troj/Weelsof-FG'], "+
			    	  "  'md5Hashes': ["+
			    	  "    'cc3223eca31b00692fa49e63ac88139b'],"+
			    	  "  'sha1Hashes': ["+
			    	  "    'b2a166c4d67f324a6ae87e142040f932ccbb596d'],"+
			    	  "  'filesCreated': ["+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\Local Settings\\\\Application Data\\\\nfdenoin.exe'],"+
			    	  "  'processesCreated': ["+
			    	  "    'c:\\\\windows\\\\system32\\\\svchost.exe'],"+
			    	  "  'registryKeysCreated': ["+
			    	  "    'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"+
			    	  "    'HKCU\\\\Software\\\\fopnellh'],"+
            		  "  'ipConnections': ["+
            		  "    '176.123.0.160:8080',"+
            		  "    '195.5.208.87:8080',"+
            		  "    '195.65.173.133:8080',"+
            		  "    '222.124.143.12:8080',"+
            		  "    '46.105.117.13:8080'],"+
			    	  "  '_type': 'vertex',"+
			    	  "  'modifiedDate': 1408392967000,"+
			    	  "  'signatureDate': 1408392967000,"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  '_id': 'Troj/Weelsof-FG',"+
			    	  "  'source': 'Sophos',"+
			    	  "  'name': 'Troj/Weelsof-FG',"+
			    	  "  'knownFileTypes': ['application/x-ms-dos-executable'],"+
			    	  "  'discoveryDate': 1408334400000"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	
	/**
	 * Test with "Troj~MSIL-ACB" sample data
	 */
	@Test
	public void test_Troj_MSIL_ACB()
	{
		String entryName = "Troj~MSIL-ACB";
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Windows',"+
			    	  "  'prevalence': 'Small Number of Reports',"+
			    	  "  'aliases': [ "+
			    	  "    'TR/Dropper.MSIL.Gen8',"+
			    	  "    'Troj/MSIL-ACB'], "+
			    	  "  'md5Hashes': ["+
			    	  "    'c5579ab457536d2fbd48e0a3bc6dc458'],"+
			    	  "  'sha1Hashes': ["+
			    	  "    '4122be8402684403e480aaf5b37caf3b727d8077'],"+
			    	  "  'filesCreated': ["+
			    	  "    'c:\\\\Documents and Settings\\\\test user\\\\Local Settings\\\\Temp\\\\141781.bat'],"+
			    	  "  'processesCreated': ["+
			    	  "    'c:\\\\windows\\\\system32\\\\cmd.exe'],"+
			    	  "  'registryKeysCreated': ["+
			    	  "    'HKCU\\\\Software\\\\WinRAR'],"+
            		  "  'dnsRequests': ["+
            		  "    'riseandshine.favcc1.com'],"+
            		  "  'urlsUsed': ["+
            		  "    'http://riseandshine.favcc1.com/gate.php'],"+
			    	  "  '_type': 'vertex',"+
			    	  "  'modifiedDate': 1408392967000,"+
			    	  "  'signatureDate': 1408392967000,"+
			    	  "  'malwareType': ['Trojan'],"+
			    	  "  '_id': 'Troj/MSIL-ACB',"+
			    	  "  'source': 'Sophos',"+
			    	  "  'name': 'Troj/MSIL-ACB',"+
			    	  "  'knownFileTypes': ['application/x-ms-dos-executable'],"+
			    	  "  'discoveryDate': 1408334400000"+
			    	  "}]";
		    String expectedEdges = "[]";
		    
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(verts, new JSONArray(expectedVerts)));
		    assertTrue( HTMLExtractor.deepCompareJSONArrays(edges, new JSONArray(expectedEdges)));
		    
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

}
