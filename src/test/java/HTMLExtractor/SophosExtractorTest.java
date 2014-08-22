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
 * Unit test for simple App.
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
	 * Tests conversion
	 */
	@Test
	public void testConvert()
	{
		//String entryName = "Mal~Conficker-A";
		//String entryName = "Troj~FBJack-A";
		//String entryName = "Troj~JsRedir-NN";
		//String entryName = "Troj~Agent-DP";
		String entryName = "Troj~Zbot-ITY";
		//String entryName = "Troj~Weelsof-FG";
		//String entryName = "Troj~MSIL-ACB";
		//String entryName = "Troj~Zbot-AAA";
		//String entryName = "Troj~MSIL-ACY"; //remote
		boolean localMode = true;
		String summary, details;
		
		try {
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			//TODO maybe add a SophosExtractor(Map)?
			SophosExtractor sophosExt = new SophosExtractor(summary, details);
			JSONObject obj = sophosExt.getGraph();
		    
		    System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		  //TODO...asserts
		    /*
		    {
		    	  "edges": [],
		    	  "vertices": [{
		    	    "platform": "Windows",
		    	    "filesCreated": [
		    	      "c:\\Documents and Settings\\test user\\Application Data\\Poce\\anyn.ezo",
		    	      "c:\\Documents and Settings\\test user\\Application Data\\Veufno\\buerx.exe"
		    	    ],
		    	    "prevalence": "Small Number of Reports",
		    	    "registryKeysModified": [
		    	      "HKCU\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Software\\Microsoft\\Outlook Express\\5.0",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\UnreadMail\\user@example.com"
		    	    ],
		    	    "filesModified": [
		    	      "%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Folders.dbx",
		    	      "%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Inbox.dbx",
		    	      "%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Offline.dbx"
		    	    ],
		    	    "type": "Trojan",
		    	    "aliases": ["Gen:Variant.Graftor.150885"],
		    	    "modifiedDate": 1408162427000,
		    	    "vertexType": "malware",
		    	    "_type": "vertex",
		    	    "category": "Viruses and Spyware",
		    	    "signatureDate": 1408162427000,
		    	    "_id": "Troj/Zbot-ITY",
		    	    "source": "Sophos",
		    	    "knownMD5Hashes": [
		    	      "599990d8fa3d211b0b775d82dd939526",
		    	      "ca2fe00295a6255ced2778fb9f43146f"
		    	    ],
		    	    "name": "Troj/Zbot-ITY",
		    	    "knownFileTypes": ["Windows executable"],
		    	    "httpRequests": [
		    	      "http://www.google.com/webhp",
		    	      "http://www.google.ie/webhp"
		    	    ],
		    	    "processesCreated": [
		    	      "c:\\Documents and Settings\\test user\\application data\\veufno\\buerx.exe",
		    	      "c:\\windows\\system32\\cmd.exe",
		    	      "c:\\windows\\system32\\hostname.exe",
		    	      "c:\\windows\\system32\\ipconfig.exe",
		    	      "c:\\windows\\system32\\tasklist.exe"
		    	    ],
		    	    "discoveryDate": 1407902400000,
		    	    "dnsRequests": [
		    	      "franciz-industries.biz",
		    	      "www.google.com",
		    	      "www.google.ie"
		    	    ],
		    	    "knownSha1Hashes": [
		    	      "8bff3c73c92314a7d094a0d024cf57a722b0b198",
		    	      "9017bd0da5f94f4ba899e5d990c8c4f4792d6876"
		    	    ],
		    	    "registryKeysCreated": [
		    	      "HKCU\\Identities",
		    	      "HKCU\\Software\\Microsoft\\Dyxol",
		    	      "HKCU\\Software\\Microsoft\\Internet Explorer\\Privacy",
		    	      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
		    	    ]
		    	  }],
		    	  "mode": "NORMAL"
		    	}
		    */
		    
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
