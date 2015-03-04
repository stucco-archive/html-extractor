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
		    
		    String expectedVerts = "[{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.30'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.30'" +
				  	  "},"+
				   	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.29'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.29'" +
			    	  "},"+
			    	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.28'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.28'" +
			    	  "},"+
			    	  "{"+
		    		  "  'vertexType': 'software'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  '_id': 'SSH Communications Security SSH 1.2.27'," +
		    		  "  'name': 'SSH Communications Security SSH 1.2.27'" +
			    	  "},"+
			    	  "{"+
		    		  "  'accessVector': 'LOCAL'," +
		    		  "  'Credit': 'This vulnerability was discovered by Richard Silverman &lt;slade@shore.net&gt;, and first announced by SSH Communications Security in an advisory posted to Bugtraq on January 16, 2001.'," +
		    		  "  'class': 'Design Error'," +
		    		  "  'CVE': ''," +
		    		  "  'solution': 'Solution: Patches available: SSH Communications Security SSH 1.2.27 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.28 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.29 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc SSH Communications Security SSH 1.2.30 SSH Communications SSH1 patch-ssh-1.2.30-secure.rpc http://www.ssh.com/products/ssh/patches/patch-ssh-1.2.30-secure.rpc'," +
		    		  "  'exploit': 'This exploit was contributed by Richard Silverman <slade@shore.net> : /data/vulnerabilities/exploits/ssh1-exploit.c'," +
		    		  "  'modifiedDate': 979603200000," +
		    		  "  'vertexType': 'vulnerability'," +
		    		  "  '_type': 'vertex'," +
		    		  "  'references': [],"+
		    		  "  '_id': 'Bugtraq_2222'," +
		    		  "  'source': 'Bugtraq'," +
		    		  "  'shortDescription': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability'," +
		    		  "  'description': 'SSH Secure-RPC Weak Encrypted Authentication Vulnerability SSH is a package designed to encrypt traffic between two end points using the IETF specified SSH protocol. The SSH1 package is distributed and maintained by SSH Communications Security. A problem exists which could allow the discovery of the secret key used to encrypt traffic on the local host. When using SUN-DES-1 to share keys with other hosts on the network to facilitate secure communication via protocols such as NFS and NIS+, the keys are shared between hosts using the private key of the user and a cryptographic algorithm to secure the contents of the key, which is stored on the NIS+ primary. The problem occurs when the key is encrypted with the SUN-DES-1 magic phrase prior to having done a keylogin (the keyserv does not have the users DH private key). A design flaw in the software that shares the key with the NIS+ master will inconsistently return the correct value for an attempted keyshare that has failed. A step in the private key encryption process is skipped, and the users private key is then encrypted only with the public key of the target server and the SUN-DES-1 magic phrase, a phrase that is guessable due to the way it is generated. A user from the same host can then execute a function that returns another users magic phrase, and use this to decrypt the private key of the victim. This makes it possible for a user with malicious intent to gain knowledge of a users secret key, and decrypt sensitive traffic between two hosts, with the possibility of gaining access and elevated privileges on the hosts and/or NIS+ domain. This reportedly affects the SSH2 series of the software package.'," +
		    		  "  'name': 'Bugtraq ID 2222'," +
		    		  "  'Vulnerable': [" +
		    		  "    'SSH Communications Security SSH 1.2.30'," +
		    		  "    'SSH Communications Security SSH 1.2.29'," +
		    		  "    'SSH Communications Security SSH 1.2.28'," +
		    		  "    'SSH Communications Security SSH 1.2.27'" +
		    		  "  ]," +
		    		  "  'Not_Vulnerable': ['']," +
		    		  "  'publishedDate': 979603200000," +
			    	  "}]";
		    String expectedEdges = "[{" + 
		    		  "  '_type': 'edge'," +
		    		  "  'outVType': 'software',"+
		    		  "  'source': 'Bugtraq',"+
		    		  "  '_id': 'SSH Communications Security SSH 1.2.30_hasVulnerability_Bugtraq_2222',"+
		    		  "  'description': 'SSH Communications Security SSH 1.2.30 has vulnerability Bugtraq ID 2222',"+
		    		  "  '_label': 'hasVulnerability',"+
		    		  "  '_outV': 'SSH Communications Security SSH 1.2.30',"+
		    		  "  '_inV': 'Bugtraq_2222',"+
		    		  "  'inVType': 'vulnerability'"+
			    	  "},"+
			    	  "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.29_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.29 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.29',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
				      "},"+
				      "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.28_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.28 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.28',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
				   	  "},"+
				   	  "{"+
			    	  "  '_type': 'edge',"+
			    	  "  'outVType': 'software',"+
			    	  "  'source': 'Bugtraq',"+
			    	  "  '_id': 'SSH Communications Security SSH 1.2.27_hasVulnerability_Bugtraq_2222',"+
			    	  "  'description': 'SSH Communications Security SSH 1.2.27 has vulnerability Bugtraq ID 2222',"+
			    	  "  '_label': 'hasVulnerability',"+
			    	  "  '_outV': 'SSH Communications Security SSH 1.2.27',"+
			    	  "  '_inV': 'Bugtraq_2222',"+
			    	  "  'inVType': 'vulnerability'"+
		    		  "}]";
		    
		    boolean match = HTMLExtractor.deepCompareJSONArraysUnordered(verts, new JSONArray(expectedVerts));
		    if(!match){
		    	System.out.println("Vertex list did not match!  result was: \n" + verts);
		    }
		    assertTrue( match );
		    match = HTMLExtractor.deepCompareJSONArraysUnordered(edges, new JSONArray(expectedEdges));
		    if(!match){
		    	System.out.println("Edge list did not match!  result was: \n" + edges);
		    }
		    assertTrue( match );
		    
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
