package HTMLExtractor;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import HTMLExtractor.FSecureExtractor;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit test for F-Secure extractor.
 */
public class FSecureExtractorTest {

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
			try{
				u = new URL("http://www.f-secure.com/v-descs/"+entryName+".shtml");
				pageContent = IOUtils.toString(u);
			}catch(IOException e){ //some items have this prefix instead.  TODO: cleaner handling of this case.
				u = new URL("http://www.f-secure.com/sw-desc/"+entryName+".shtml");
				pageContent = IOUtils.toString(u);
			}
		}
		return pageContent;
	}
	
	/**
	 * Test with "application_w32_installbrain" sample data
	 */
	@Test
	public void test_application_w32_installbrain()
	{
		String entryName = "application_w32_installbrain";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'W32',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'removal': 'F-Secure',"+
			    	  "  'malwareType': ['Spyware','Application'],"+
			    	  "  'overview': \"InstallBrain is an updater service that runs in the background and periodically updates associates browser plug-ins and add-ons.\","+
			    	  "  'details': \"InstallBrain is part of a software bundler program associated with various browser plug-ins and add-ons from the Perion Network software company. When installed, the application is essentially an updater service that will run in the background as 'ibsvc.exe' and periodically download and install updates for the associated browser components. The add-ons maintained by InstallBrain vary in function, but have reportedly silently reset the browser homepage and modified the search engine settings and/or search results. If the user elects to remove the components, the related InstallBrain program should also be uninstalled. As of early October 2013, some InstallBrain installers have shown code similarity to Trojan-Downloader:W32/Mevade; these installers are identified with the detection name Trojan:W32/Installbrain.[variant].\","+
			    	  "  'source': 'F-Secure',"+
			    	  "  '_id': 'Application:W32/InstallBrain',"+
			    	  "  'name': 'Application:W32/InstallBrain',"+
			    	  "  'aliases': [ 'Application:W32/InstallBrain', 'Application:W32/InstallBrain.[variant]', 'Trojan:W32/InstallBrain.[variant]']"+
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
	 * Test with "backdoor_w32_havex" sample data
	 */
	@Test
	public void test_backdoor_w32_havex()
	{
		String entryName = "backdoor_w32_havex";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'W32',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'removal': 'F-Secure',"+
			    	  "  'malwareType': ['Malware','Backdoor'],"+
			    	  "  'overview': \"Havex is a Remote Access Tool (RAT) used in targeted attacks. Once present on a machine, it scans the system and connected resources for information that may be of use in later attacks; the collected data is forwarded to remote servers.\","+
			    	  "  'details': \"Havex is known to have been used in attacks targeted against various industrial sectors, particularly the energy sector. Variants seen circulating in the spring of 2014 were modified to target organizations involved in developing or using industrial applications or appliances.\","+
			    	  "  'behavior': \"Once the Havex malware has been delivered to the targeted users and installed on a machine, it scans the system and connected resources accessible over a network for information of interest. This information includes the presence of any Industrial Control Systems (ICS) or Supervisory Control And Data Acquisition (SCADA) systems present in the network. The collected data is then forwarded to compromised websites, which surreptitiously serve as remote command and control (C&C) servers. For more technical details, see: Labs Weblog: Havex Hunts for ICS/SCADA Systems\","+
			    	  "  'distribution': \"Havex is known to be distributed to targeted users through: Spam emails Exploit kits Trojanized installers planted on compromised vendor sites For the last distribution channel, compromised vendor sites that were identified were related to companies involved in the development of applications and appliances used in industrial settings. The affected companies are based in Germany, Switzerland and Belgium.\","+
			    	  "  'source': 'F-Secure',"+
			    	  "  '_id': 'Backdoor:W32/Havex',"+
			    	  "  'name': 'Backdoor:W32/Havex',"+
			    	  "  'aliases': ['Backdoor:W32/Havex','Havex','Havex.A']"+
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
	 * Test with "trojan_html_browlock" sample data
	 */
	@Test
	public void test_trojan_html_browlock()
	{
		String entryName = "trojan_html_browlock";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    //System.out.println(verts.toString(2));
		    
		    String expectedVerts = "[{"+
		    	  "  'vertexType': 'malware',"+
		    	  "  'platform': 'HTML',"+
		    	  "  '_type': 'vertex',"+
		    	  "  'removal': 'F-Secure',"+
		    	  "  'malwareType': ['Malware','Trojan'],"+
		    	  "  'overview': \"Trojan:HTML/Browlock is ransomware that prevents users from accessing the infected machine's Desktop; it then demands payment, supposedly for either possession of illegal material or usage of illegal software.\","+
		    	  "  'details': \"Trojan:HTML/Browlock has been reported to target users in multiple countries, including the United States, the United Kingdom and Canada. Typically, it will display a 'lock screen' purportedly from a local or federal law enforcement authority, claiming that the machine has been locked and encrypted due to 'illegal activities'. A 'fine' is then demanded to restore the system. This malware was also covered in our Labs Weblog blogpost: Browlock Ransomware Targets New Countries A lock screen used by one Browlock variant is shown below: http://www.f-secure.com/weblog/archives/brow_uk.png\","+
		    	  "  'source': 'F-Secure',"+
		    	  "  '_id': 'Trojan:HTML/Browlock',"+
		    	  "  'name': 'Trojan:HTML/Browlock',"+
		    	  "  'aliases': ['Trojan:HTML/Browlock','Trojan:HTML/Browlock.[variant]']"+
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
	 * Test with "trojan_android_droidkungfu_c" sample data
	 */
	@Test
	public void test_trojan_android_droidkungfu_c()
	{
		String entryName = "trojan_android_droidkungfu_c";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'Android',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'malwareType': ['Malware','Trojan'],"+
			    	  "  'overview': \"Trojan:Android/DroidKungFu.C forwards confidential details to a remote server.\","+
			    	  "  'details': \"Trojan:Android/DroidKungFu.C are distributed on unauthorized Android app sites as trojanized versions of legitimate applications.\","+
			    	  "  'source': 'F-Secure',"+
			    	  "  '_id': 'Trojan:Android/DroidKungFu.C',"+
			    	  "  'name': 'Trojan:Android/DroidKungFu.C',"+
			    	  "  'aliases': [ "+
			    	  "    'DroidKungFu',"+
			    	  "    'DroidKungFu.C',"+
			    	  "    'Trojan:Android/DroidKungFu.C']"+
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
	 * Test with "trojan_bash_qhost_wb" sample data
	 */
	@Test
	public void test_trojan_bash_qhost_wb()
	{
		String entryName = "trojan_bash_qhost_wb";
		boolean localMode = true;
		String pageContent;
		
		try {
			pageContent = loadContent(entryName, localMode);
			
			FSecureExtractor bugtraqExt = new FSecureExtractor(pageContent);
			JSONObject obj = bugtraqExt.getGraph();
		    
		    //System.out.println(obj.toString(2));

		    JSONArray verts = obj.getJSONArray("vertices");
		    JSONArray edges = obj.getJSONArray("edges");
		    
		    String expectedVerts = "[{"+
			    	  "  'vertexType': 'malware',"+
			    	  "  'platform': 'BASH',"+
			    	  "  '_type': 'vertex',"+
			    	  "  'malwareType': ['Malware','Trojan'],"+
			    	  "  'overview': \"Trojan:BASH/QHost.WB hijacks web traffic by modifying the hosts file.\","+
			    	  "  'details': \"Trojan:BASH/QHost.WB poses as a FlashPlayer installer called FlashPlayer.pkg:\","+
			    	  "  'source': 'F-Secure',"+
			    	  "  '_id': 'Trojan:BASH/QHost.WB',"+
			    	  "  'name': 'Trojan:BASH/QHost.WB',"+
			    	  "  'aliases': [ "+
			    	  "    'BASH/QHost.WB',"+
			    	  "    'QHost',"+
			    	  "    'QHost.WB',"+
			    	  "    'Trojan:BASH/QHost.WB']"+
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
