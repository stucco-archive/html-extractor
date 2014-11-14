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
		    
		    String expectedVerts = "["+
		    		"  {"+
		    		"    'vertexType': 'port',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '80',"+
		    		"    'name': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'Address',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'franciz-industries.biz:80',"+
		    		"    'name': 'franciz-industries.biz:80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'DNSName',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'franciz-industries.biz',"+
		    		"    'name': 'franciz-industries.biz'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'port',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '80',"+
		    		"    'name': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'Address',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.com:80',"+
		    		"    'name': 'www.google.com:80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'DNSName',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.com',"+
		    		"    'name': 'www.google.com'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'port',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '80',"+
		    		"    'name': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'Address',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.ie:80',"+
		    		"    'name': 'www.google.ie:80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'DNSName',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.ie',"+
		    		"    'name': 'www.google.ie'"+
		    		"  },"+
		    		"  {"+
		    		"    'platform': 'Windows',"+
		    		"    'filesCreated': ["+
		    		"      'c:\\\\Documents and Settings\\\\test user\\\\Application Data\\\\Poce\\\\anyn.ezo',"+
		    		"      'c:\\\\Documents and Settings\\\\test user\\\\Application Data\\\\Veufno\\\\buerx.exe'"+
		    		"    ],"+
		    		"    'prevalence': 'Small Number of Reports',"+
		    		"    'md5Hashes': ["+
		    		"      '599990d8fa3d211b0b775d82dd939526',"+
		    		"      'ca2fe00295a6255ced2778fb9f43146f'"+
		    		"    ],"+
		    		"    'registryKeysModified': ["+
		    		"      'HKCU\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Software\\\\Microsoft\\\\Outlook Express\\\\5.0',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\0',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\1',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\2',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Zones\\\\4',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\UnreadMail\\\\user@example.com'"+
		    		"    ],"+
		    		"    'filesModified': ["+
		    		"      '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Folders.dbx',"+
		    		"      '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Inbox.dbx',"+
		    		"      '%PROFILE%\\\\Local Settings\\\\Application Data\\\\Identities\\\\{E2564744-A8ED-497D-924B-A548B20CA034}\\\\Microsoft\\\\Outlook Express\\\\Offline.dbx'"+
		    		"    ],"+
		    		"    'aliases': ["+
		    		"      'Gen:Variant.Graftor.150885',"+
		    		"      'Troj/Zbot-ITY'"+
		    		"    ],"+
		    		"    'sha1Hashes': ["+
		    		"      '8bff3c73c92314a7d094a0d024cf57a722b0b198',"+
		    		"      '9017bd0da5f94f4ba899e5d990c8c4f4792d6876'"+
		    		"    ],"+
		    		"    'modifiedDate': 1408162427000,"+
		    		"    'urlsUsed': ["+
		    		"      'http://www.google.com/webhp',"+
		    		"      'http://www.google.ie/webhp'"+
		    		"    ],"+
		    		"    'vertexType': 'malware',"+
		    		"    '_type': 'vertex',"+
		    		"    'signatureDate': 1408162427000,"+
		    		"    'malwareType': ['Trojan'],"+
		    		"    '_id': 'Troj/Zbot-ITY',"+
		    		"    'source': 'Sophos',"+
		    		"    'name': 'Troj/Zbot-ITY',"+
		    		"    'knownFileTypes': ['Windows executable'],"+
		    		"    'processesCreated': ["+
		    		"      'c:\\\\Documents and Settings\\\\test user\\\\application data\\\\veufno\\\\buerx.exe',"+
		    		"      'c:\\\\windows\\\\system32\\\\cmd.exe',"+
		    		"      'c:\\\\windows\\\\system32\\\\hostname.exe',"+
		    		"      'c:\\\\windows\\\\system32\\\\ipconfig.exe',"+
		    		"      'c:\\\\windows\\\\system32\\\\tasklist.exe'"+
		    		"    ],"+
		    		"    'discoveryDate': 1407902400000,"+
		    		"    'registryKeysCreated': ["+
		    		"      'HKCU\\\\Identities',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Dyxol',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Internet Explorer\\\\Privacy',"+
		    		"      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'"+
		    		"    ]"+
		    		"  }"+
			    	  "]";
		    String expectedEdges = "["+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Zbot-ITY_to_franciz-industries.biz:80',"+
		    		"    '_outV': 'Troj/Zbot-ITY',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': 'franciz-industries.biz:80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'franciz-industries.biz:80_to_80',"+
		    		"    '_outV': 'franciz-industries.biz:80',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'franciz-industries.biz:80_to_franciz-industries.biz',"+
		    		"    '_outV': 'franciz-industries.biz:80',"+
		    		"    '_label': 'hasDNSName',"+
		    		"    'inVType': 'DNSName',"+
		    		"    '_inV': 'franciz-industries.biz'"+
		    		"  },"+
		    	    "  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Zbot-ITY_to_www.google.com:80',"+
		    		"    '_outV': 'Troj/Zbot-ITY',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': 'www.google.com:80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.com:80_to_80',"+
		    		"    '_outV': 'www.google.com:80',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.com:80_to_www.google.com',"+
		    		"    '_outV': 'www.google.com:80',"+
		    		"    '_label': 'hasDNSName',"+
		    		"    'inVType': 'DNSName',"+
		    		"    '_inV': 'www.google.com'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Zbot-ITY_to_www.google.ie:80',"+
		    		"    '_outV': 'Troj/Zbot-ITY',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': 'www.google.ie:80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.ie:80_to_80',"+
		    		"    '_outV': 'www.google.ie:80',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'www.google.ie:80_to_www.google.ie',"+
		    		"    '_outV': 'www.google.ie:80',"+
		    		"    '_label': 'hasDNSName',"+
		    		"    'inVType': 'DNSName',"+
		    		"    '_inV': 'www.google.ie'"+
		    		"  }"+
		    		  "]";
		    
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
		    
		    String expectedVerts = "["+
		    		"  {"+
		            "    'vertexType': 'port',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '8080',"+
		            "    'name': '8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'Address',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '176.123.0.160:8080',"+
		            "    'name': '176.123.0.160:8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'ip',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '176.123.0.160',"+
		            "    'name': '176.123.0.160'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'port',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '8080',"+
		            "    'name': '8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'Address',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '195.5.208.87:8080',"+
		            "    'name': '195.5.208.87:8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'ip',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '195.5.208.87',"+
		            "    'name': '195.5.208.87'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'port',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '8080',"+
		            "    'name': '8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'Address',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '195.65.173.133:8080',"+
		            "    'name': '195.65.173.133:8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'ip',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '195.65.173.133',"+
		            "    'name': '195.65.173.133'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'port',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '8080',"+
		            "    'name': '8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'Address',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '222.124.143.12:8080',"+
		            "    'name': '222.124.143.12:8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'ip',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '222.124.143.12',"+
		            "    'name': '222.124.143.12'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'port',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '8080',"+
		            "    'name': '8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'Address',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '46.105.117.13:8080',"+
		            "    'name': '46.105.117.13:8080'"+
		            "  },"+
		            "  {"+
		            "    'vertexType': 'ip',"+
		            "    '_type': 'vertex',"+
		            "    'source': 'Sophos',"+
		            "    '_id': '46.105.117.13',"+
		            "    'name': '46.105.117.13'"+
		            "  },"+
		            "  {"+
		            "    'platform': 'Windows',"+
		            "    'filesCreated': ['c:\\\\Documents and Settings\\\\test user\\\\Local Settings\\\\Application Data\\\\nfdenoin.exe'],"+
		            "    'prevalence': 'Small Number of Reports',"+
		            "    'md5Hashes': ['cc3223eca31b00692fa49e63ac88139b'],"+
		            "    'aliases': ["+
		            "      'TR/Crypt.XPACK.Gen7',"+
		            "      'Troj/Weelsof-FG'"+
		            "    ],"+
		            "    'sha1Hashes': ['b2a166c4d67f324a6ae87e142040f932ccbb596d'],"+
		            "    'modifiedDate': 1408392967000,"+
		            "    'vertexType': 'malware',"+
		            "    '_type': 'vertex',"+
		            "    'signatureDate': 1408392967000,"+
		            "    'malwareType': ['Trojan'],"+
		            "    '_id': 'Troj/Weelsof-FG',"+
		            "    'source': 'Sophos',"+
		            "    'name': 'Troj/Weelsof-FG',"+
		            "    'knownFileTypes': ['application/x-ms-dos-executable'],"+
		            "    'processesCreated': ['c:\\\\windows\\\\system32\\\\svchost.exe'],"+
		            "    'discoveryDate': 1408334400000,"+
		            "    'registryKeysCreated': ["+
		            "      'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',"+
		            "      'HKCU\\\\Software\\\\fopnellh'"+
		            "    ]"+
		            "  }"+
			    	  "]";
		    String expectedEdges = "["+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Weelsof-FG_to_176.123.0.160:8080',"+
		    		"    '_outV': 'Troj/Weelsof-FG',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': '176.123.0.160:8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '176.123.0.160:8080_to_8080',"+
		    		"    '_outV': '176.123.0.160:8080',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '176.123.0.160:8080_to_176.123.0.160',"+
		    		"    '_outV': '176.123.0.160:8080',"+
		    		"    '_label': 'hasIP',"+
		    		"    'inVType': 'ip',"+
		    		"    '_inV': '176.123.0.160'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Weelsof-FG_to_195.5.208.87:8080',"+
		    		"    '_outV': 'Troj/Weelsof-FG',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': '195.5.208.87:8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '195.5.208.87:8080_to_8080',"+
		    		"    '_outV': '195.5.208.87:8080',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '195.5.208.87:8080_to_195.5.208.87',"+
		    		"    '_outV': '195.5.208.87:8080',"+
		    		"    '_label': 'hasIP',"+
		    		"    'inVType': 'ip',"+
		    		"    '_inV': '195.5.208.87'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Weelsof-FG_to_195.65.173.133:8080',"+
		    		"    '_outV': 'Troj/Weelsof-FG',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': '195.65.173.133:8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '195.65.173.133:8080_to_8080',"+
		    		"    '_outV': '195.65.173.133:8080',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '195.65.173.133:8080_to_195.65.173.133',"+
		    		"    '_outV': '195.65.173.133:8080',"+
		    		"    '_label': 'hasIP',"+
		    		"    'inVType': 'ip',"+
		    		"    '_inV': '195.65.173.133'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Weelsof-FG_to_222.124.143.12:8080',"+
		    		"    '_outV': 'Troj/Weelsof-FG',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': '222.124.143.12:8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '222.124.143.12:8080_to_8080',"+
		    		"    '_outV': '222.124.143.12:8080',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '222.124.143.12:8080_to_222.124.143.12',"+
		    		"    '_outV': '222.124.143.12:8080',"+
		    		"    '_label': 'hasIP',"+
		    		"    'inVType': 'ip',"+
		    		"    '_inV': '222.124.143.12'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/Weelsof-FG_to_46.105.117.13:8080',"+
		    		"    '_outV': 'Troj/Weelsof-FG',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': '46.105.117.13:8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '46.105.117.13:8080_to_8080',"+
		    		"    '_outV': '46.105.117.13:8080',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '8080'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '46.105.117.13:8080_to_46.105.117.13',"+
		    		"    '_outV': '46.105.117.13:8080',"+
		    		"    '_label': 'hasIP',"+
		    		"    'inVType': 'ip',"+
		    		"    '_inV': '46.105.117.13'"+
		    		"  }"+
		    		  "]";
		    
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
		    
		    String expectedVerts = "["+
		    		"  {"+
		    		"    'vertexType': 'port',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': '80',"+
		    		"    'name': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'Address',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'riseandshine.favcc1.com:80',"+
		    		"    'name': 'riseandshine.favcc1.com:80'"+
		    		"  },"+
		    		"  {"+
		    		"    'vertexType': 'DNSName',"+
		    		"    '_type': 'vertex',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'riseandshine.favcc1.com',"+
		    		"    'name': 'riseandshine.favcc1.com'"+
		    		"  },"+
		    		"  {"+
		    		"    'platform': 'Windows',"+
		    		"    'filesCreated': ['c:\\\\Documents and Settings\\\\test user\\\\Local Settings\\\\Temp\\\\141781.bat'],"+
		    		"    'prevalence': 'Small Number of Reports',"+
		    		"    'md5Hashes': ['c5579ab457536d2fbd48e0a3bc6dc458'],"+
		    		"    'aliases': ["+
		    		"      'TR/Dropper.MSIL.Gen8',"+
		    		"      'Troj/MSIL-ACB'"+
		    		"    ],"+
		    		"    'sha1Hashes': ['4122be8402684403e480aaf5b37caf3b727d8077'],"+
		    		"    'modifiedDate': 1408392967000,"+
		    		"    'urlsUsed': ['http://riseandshine.favcc1.com/gate.php'],"+
		    		"    'vertexType': 'malware',"+
		    		"    '_type': 'vertex',"+
		    		"    'signatureDate': 1408392967000,"+
		    		"    'malwareType': ['Trojan'],"+
		    		"    '_id': 'Troj/MSIL-ACB',"+
		    		"    'source': 'Sophos',"+
		    		"    'name': 'Troj/MSIL-ACB',"+
		    		"    'knownFileTypes': ['application/x-ms-dos-executable'],"+
		    		"    'processesCreated': ['c:\\\\windows\\\\system32\\\\cmd.exe'],"+
		    		"    'discoveryDate': 1408334400000,"+
		    		"    'registryKeysCreated': ['HKCU\\\\Software\\\\WinRAR']"+
		    		"  }"+
			    	  "]";
		    String expectedEdges = "["+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'malware',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'Troj/MSIL-ACB_to_riseandshine.favcc1.com:80',"+
		    		"    '_outV': 'Troj/MSIL-ACB',"+
		    		"    '_label': 'communicatesWith',"+
		    		"    'inVType': 'address',"+
		    		"    '_inV': 'riseandshine.favcc1.com:80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'riseandshine.favcc1.com:80_to_80',"+
		    		"    '_outV': 'riseandshine.favcc1.com:80',"+
		    		"    '_label': 'hasPort',"+
		    		"    'inVType': 'port',"+
		    		"    '_inV': '80'"+
		    		"  },"+
		    		"  {"+
		    		"    '_type': 'edge',"+
		    		"    'outVType': 'address',"+
		    		"    'source': 'Sophos',"+
		    		"    '_id': 'riseandshine.favcc1.com:80_to_riseandshine.favcc1.com',"+
		    		"    '_outV': 'riseandshine.favcc1.com:80',"+
		    		"    '_label': 'hasDNSName',"+
		    		"    'inVType': 'DNSName',"+
		    		"    '_inV': 'riseandshine.favcc1.com'"+
		    		"  }"+
		    		  "]";
		    
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
