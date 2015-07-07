package HTMLExtractor;

import java.util.*;
import java.util.List;
import java.util.ArrayList;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.XML;

import HTMLExtractor.FSecureExtractor;

import org.junit.Test;

import static org.junit.Assert.*;
	
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.ttp_1.VictimTargetingType;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.ttp_1.InfrastructureType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.indicator_2.SuggestedCOAsType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ContributingSourcesType;
import org.mitre.stix.common_1.IdentityType;
import org.mitre.cybox.common_2.TimeType;
import org.mitre.stix.common_1.TTPBaseType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.common_1.RelatedTTPType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.AttackPatternsType;
import org.mitre.stix.ttp_1.AttackPatternType;
import javax.xml.namespace.QName;

/**
 * Unit test for F-Secure extractor.
 */
public class FSecureToStixExtractorTest {

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
					
	private JSONObject StixToJSON(STIXPackage fsecurePackage)	{
					
		JSONObject jsonPackage = new JSONObject();
		JSONArray jsonArray = new JSONArray();

		String name, source, details, description, removal, distribution, behavior, vertexType, platform, malwareType;
		List<String> aliases = new ArrayList<String>();
		List<String> malwareTypes = new ArrayList<String>();

		if (fsecurePackage.getIndicators() != null)	{
			if (fsecurePackage.getIndicators().getIndicators() != null)	{
				List<IndicatorBaseType> indicators = fsecurePackage.getIndicators().getIndicators();
				for (int i = 0; i < indicators.size(); i++)	{
					Indicator indicator = (Indicator) indicators.get(i);
					if (indicator.getAlternativeIDs() != null)	{
						aliases = indicator.getAlternativeIDs();
						jsonPackage.put("aliases", aliases);
					}
					if (indicator.getSuggestedCOAs().getSuggestedCOAs() != null) {
						List<RelatedCourseOfActionType> relatedCOA = indicator.getSuggestedCOAs().getSuggestedCOAs();
						for (int k = 0; k < relatedCOA.size(); k++)	{
 							CourseOfAction coa = (CourseOfAction)relatedCOA.get(k).getCourseOfAction();
							List<StructuredTextType> removalList = coa.getDescriptions();
							for (int a = 0; a < removalList.size(); a++)	{
								//stix keeps removal as a list, but we should have only one entree
								removal = removalList.get(a).getValue();		
								jsonPackage.put("removal", removal);
							}
						}
												
						List<RelatedTTPType> relatedTTP = indicator.getIndicatedTTPs();
						for (int k = 0; k < relatedTTP.size(); k++)	{
							TTP ttp = (TTP)relatedTTP.get(k).getTTP();
							
							List<MalwareInstanceType> malwareInstance = ttp.getBehavior().getMalware().getMalwareInstances();
							if (malwareInstance.size() != 0) vertexType = "malware";
							for (int a = 0; a < malwareInstance.size(); a++)	{
								
								List types = malwareInstance.get(a).getTypes();
								jsonPackage.put("malwareType", types);
														
								List<ControlledVocabularyStringType> names = malwareInstance.get(a).getNames();
								for (int b = 0; b < names.size(); b++)	{
									System.out.println(names.get(b).getValue());
									name = names.get(b).getValue().toString();			//assume there is only one name ....
									jsonPackage.put("name", name);
								}
								List<StructuredTextType> descriptions = malwareInstance.get(a).getDescriptions();
								for (int b = 0; b < descriptions.size(); b++)	{
									System.out.println(descriptions.get(b).getValue());
									description = descriptions.get(b).getValue();	//assume there is just one description ...
									jsonPackage.put("description", description);
								}
							}
																						
							List<AttackPatternType> attackPatterns = ttp.getBehavior().getAttackPatterns().getAttackPatterns();
							for (int a = 0; a < attackPatterns.size(); a++)	{
								String title = attackPatterns.get(a).getTitle();
								System.out.println(title);
								List<StructuredTextType> descriptions = attackPatterns.get(a).getDescriptions();
								for (int c = 0; c < descriptions.size(); c++)	{
									System.out.println(descriptions.get(c).getValue());
									if (title.equals("Distribution"))	{
										distribution = descriptions.get(c).getValue();
										jsonPackage.put("Distribution", distribution);
									}
									if (title.equals("Details"))	{
										details = descriptions.get(c).getValue();
										jsonPackage.put("Details", details);
									}
								}
							}
																		
							List<ControlledVocabularyStringType> platforms = ttp.getVictimTargeting().getTargetedSystems();
							for (int a = 0; a < platforms.size(); a++)	{
								System.out.println(platforms.get(a));
								platform = platforms.get(a).getValue().toString();
								jsonPackage.put("platform", platform);
							}
																
					//		if (ttp.getInformationSource().getIdentity().getName() != null)	{
					//			source = ttp.getInformationSource().getIdentity().getName();
					//			jsonPackage.put("source", source);
					//		}
						}

					//	behavior = indicator.getObservable().getDescription().getValue();
					//	jsonPackage.put("behavior", behavior);		
					}							
				}
			}
		}
		

		return jsonPackage;
	}

	private JSONObject removeEmptyFields (JSONObject jsonObject)	{

		if (jsonObject == null) return null;
							
		Iterator<String> keys = jsonObject.keys();
		while(keys.hasNext())	{
			String key = keys.next();
			if (jsonObject.get(key) instanceof JSONObject)	{
				if (jsonObject.isNull(key)) keys.remove();
				else removeEmptyFields(jsonObject.getJSONObject(key));	
			}
			else if (jsonObject.get(key) instanceof JSONArray)	{
				if (jsonObject.getJSONArray(key).length() == 0)	keys.remove();
				else	{
					for (int i = 0; i < jsonObject.getJSONArray(key).length(); i++)	{
						removeEmptyFields(jsonObject.getJSONArray(key).optJSONObject(i));
					}	
				}
			}
			else if (jsonObject.isNull(key))
				keys.remove();
		}
		
		return jsonObject;
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
			
			FSecureToStixExtractor fsecureExt = new FSecureToStixExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println(fsecurePackage.toXMLString(true));
			assertTrue(fsecureExt.validate(fsecurePackage));
														
			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"id=\"stucco:F-Secure-552152da-2589-4f92-87fb-35ae089e484a\" " +
				"timestamp=\"2015-07-07T15:27:30.237Z\" " +
				"xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"xmlns:stucco=\"stucco\" " + 
				"xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"<stix:STIX_Header> " +
				"<stix:Title>F-Secure</stix:Title> " +
				"</stix:STIX_Header> " +
				"<stix:Indicators> " +
				"<stix:Indicator " +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"<indicator:Type>Malware</indicator:Type> " +							
				"<indicator:Alternative_ID>Application:W32/InstallBrain</indicator:Alternative_ID> " +
				"<indicator:Alternative_ID>Application:W32/InstallBrain.[variant]</indicator:Alternative_ID> " +
				"<indicator:Alternative_ID>Trojan:W32/InstallBrain.[variant]</indicator:Alternative_ID> " +
				"<indicator:Observable/> " + 
				"<indicator:Indicated_TTP> " +
				"<stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"<ttp:Behavior> " + 
				"<ttp:Attack_Patterns> " +
				"<ttp:Attack_Pattern> " +
				"<ttp:Title>Details</ttp:Title> " +																		
				"<ttp:Description>InstallBrain is part of a software bundler program associated with various browser plug-ins and add-ons from the Perion Network software company. When installed, the application is essentially an updater service that will run in the background as 'ibsvc.exe' and periodically download and install updates for the associated browser components. The add-ons maintained by InstallBrain vary in function, but have reportedly silently reset the browser homepage and modified the search engine settings and/or search results. If the user elects to remove the components, the related InstallBrain program should also be uninstalled. As of early October 2013, some InstallBrain installers have shown code similarity to Trojan-Downloader:W32/Mevade; these installers are identified with the detection name Trojan:W32/Installbrain.[variant].</ttp:Description> " +
				"</ttp:Attack_Pattern> " +
				"</ttp:Attack_Patterns> " +
				"<ttp:Malware> " +
				"<ttp:Malware_Instance> " +
				"<ttp:Type>Spyware</ttp:Type> " +
				"<ttp:Type>Application</ttp:Type> " +
				"<ttp:Name>Application:W32/InstallBrain</ttp:Name> " + 
				"<ttp:Description>InstallBrain is an updater service that runs in the background and periodically updates associates browser plug-ins and add-ons.</ttp:Description> " + 
				"</ttp:Malware_Instance> " + 
				"</ttp:Malware> " + 
				"</ttp:Behavior>  " + 
				"<ttp:Victim_Targeting> " +
				"<ttp:Targeted_Systems>W32</ttp:Targeted_Systems> " +
				"</ttp:Victim_Targeting> " +
				"<ttp:Information_Source>  " +
				"<stixCommon:Contributing_Sources> " +
				"<stixCommon:Source> " +
				"<stixCommon:Identity> " +
				"<stixCommon:Name>F-Secure</stixCommon:Name> " +
				"</stixCommon:Identity> " +
				"</stixCommon:Source> " +
				"</stixCommon:Contributing_Sources> " +
				"</ttp:Information_Source> " +
				"</stixCommon:TTP> " +
				"</indicator:Indicated_TTP> " +
				"<indicator:Suggested_COAs> " + 
				"<indicator:Suggested_COA> " + 
				"<stixCommon:Course_Of_Action xsi:type=\"coa:CourseOfActionType\"> " +
				"<coa:Description>F-Secure</coa:Description> " +
				"</stixCommon:Course_Of_Action> " +
				"</indicator:Suggested_COA> " +
				"</indicator:Suggested_COAs> " +
				"</stix:Indicator> " +
				"</stix:Indicators> " + 
				"</stix:STIX_Package>";			


			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			
			assertEquals(expectedPackage.getIndicators(), fsecurePackage.getIndicators());
										
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
		    
			
			FSecureToStixExtractor fsecureExt = new FSecureToStixExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println(fsecurePackage.toXMLString(true));
			assertTrue(fsecureExt.validate(fsecurePackage));

			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"id=\"stucco:F-Secure-a541ac53-e1fb-415d-a293-65fb5e34cddb\" " +
				"timestamp=\"2015-07-07T18:08:08.998Z\" " +
				"xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"<stix:STIX_Header> " +
				"<stix:Title>F-Secure</stix:Title> " +
				"</stix:STIX_Header> " +
				"<stix:Indicators> " +
				"<stix:Indicator  " + 
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"<indicator:Type>Malware</indicator:Type> " +							
				"<indicator:Alternative_ID>Backdoor:W32/Havex</indicator:Alternative_ID> " +
				"<indicator:Alternative_ID>Havex</indicator:Alternative_ID> " +
				"<indicator:Alternative_ID>Havex.A</indicator:Alternative_ID> " +
				"<indicator:Observable> " +
				"<cybox:Description>Once the Havex malware has been delivered to the targeted users and installed on a machine, it scans the system and connected resources accessible over a network for information of interest. This information includes the presence of any Industrial Control Systems (ICS) or Supervisory Control And Data Acquisition (SCADA) systems present in the network. The collected data is then forwarded to compromised websites, which surreptitiously serve as remote command and control (C&amp;C) servers. For more technical details, see: Labs Weblog: Havex Hunts for ICS/SCADA Systems</cybox:Description> " +
				"</indicator:Observable> " +
				"<indicator:Indicated_TTP> " +
				"<stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"<ttp:Behavior> " +
				"<ttp:Attack_Patterns> " +
				"<ttp:Attack_Pattern> " +
				"<ttp:Title>Distribution</ttp:Title> " +
				"<ttp:Description>Havex is known to be distributed to targeted users through: Spam emails Exploit kits Trojanized installers planted on compromised vendor sites For the last distribution channel, compromised vendor sites that were identified were related to companies involved in the development of applications and appliances used in industrial settings. The affected companies are based in Germany, Switzerland and Belgium.</ttp:Description> " +
				"</ttp:Attack_Pattern> " +
				"<ttp:Attack_Pattern> " +
                                "<ttp:Title>Details</ttp:Title> " +
				"<ttp:Description>Havex is known to have been used in attacks targeted against various industrial sectors, particularly the energy sector. Variants seen circulating in the spring of 2014 were modified to target organizations involved in developing or using industrial applications or appliances.</ttp:Description> " +
				"</ttp:Attack_Pattern> " +
				"</ttp:Attack_Patterns> " +
				"<ttp:Malware> " +
				"<ttp:Malware_Instance> " +
				"<ttp:Type>Malware</ttp:Type> " +
				"<ttp:Type>Backdoor</ttp:Type> " +
				"<ttp:Name>Backdoor:W32/Havex</ttp:Name> " +
				"<ttp:Description>Havex is a Remote Access Tool (RAT) used in targeted attacks. Once present on a machine, it scans the system and connected resources for information that may be of use in later attacks; the collected data is forwarded to remote servers.</ttp:Description> " +
				"</ttp:Malware_Instance> " +
				"</ttp:Malware> " +
				"</ttp:Behavior> " +
				"<ttp:Victim_Targeting> " +
				"<ttp:Targeted_Systems>W32</ttp:Targeted_Systems> " +
				"</ttp:Victim_Targeting> " +
				"<ttp:Information_Source> " +
				"<stixCommon:Contributing_Sources> " +
				"<stixCommon:Source> " +
				"<stixCommon:Identity> " +
				"<stixCommon:Name>F-Secure</stixCommon:Name> " +
				"</stixCommon:Identity> " +
				"</stixCommon:Source> " +
				"</stixCommon:Contributing_Sources> " +
				"</ttp:Information_Source> " +
				"</stixCommon:TTP> " +
				"</indicator:Indicated_TTP> " +
				"<indicator:Suggested_COAs> " +
				"<indicator:Suggested_COA> " +
				"<stixCommon:Course_Of_Action xsi:type=\"coa:CourseOfActionType\">" + 
				"<coa:Description>F-Secure</coa:Description> " + 
				"</stixCommon:Course_Of_Action> " +
				"</indicator:Suggested_COA> " +
				"</indicator:Suggested_COAs> " +
				"</stix:Indicator> " +
				"</stix:Indicators> "+ 
				"</stix:STIX_Package>";

			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			assertEquals(expectedPackage.getIndicators(), fsecurePackage.getIndicators());

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
			
			FSecureToStixExtractor fsecureExt = new FSecureToStixExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println(fsecurePackage.toXMLString(true));
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"id=\"stucco:F-Secure-06d77ee8-68df-41ab-8326-ce3cab103d21\" " +
				"timestamp=\"2015-07-07T19:00:06.352Z\" " +
				"xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"<stix:STIX_Header>" +
				"<stix:Title>F-Secure</stix:Title>" +
				"</stix:STIX_Header>" +
				"<stix:Indicators>" +
				"<stix:Indicator " +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\">" +
				"<indicator:Type>Malware</indicator:Type>" +
				"<indicator:Alternative_ID>Trojan:HTML/Browlock</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>Trojan:HTML/Browlock.[variant]</indicator:Alternative_ID>" +
				"<indicator:Observable/>" +
				"<indicator:Indicated_TTP>" +
				"<stixCommon:TTP xsi:type=\"ttp:TTPType\">" +
				"<ttp:Behavior>" +
				"<ttp:Attack_Patterns>" +
				"<ttp:Attack_Pattern>" +
				"<ttp:Title>Details</ttp:Title>" +
				"<ttp:Description>Trojan:HTML/Browlock has been reported to target users in multiple countries, including the United States, the United Kingdom and Canada. Typically, it will display a 'lock screen' purportedly from a local or federal law enforcement authority, claiming that the machine has been locked and encrypted due to 'illegal activities'. A 'fine' is then demanded to restore the system. This malware was also covered in our Labs Weblog blogpost: Browlock Ransomware Targets New Countries A lock screen used by one Browlock variant is shown below: http://www.f-secure.com/weblog/archives/brow_uk.png</ttp:Description>" +
				"</ttp:Attack_Pattern>" +
				"</ttp:Attack_Patterns>" +
				"<ttp:Malware>" +
				"<ttp:Malware_Instance>" +
				"<ttp:Type>Malware</ttp:Type>" +
				"<ttp:Type>Trojan</ttp:Type>" +
				"<ttp:Name>Trojan:HTML/Browlock</ttp:Name>" +
				"<ttp:Description>Trojan:HTML/Browlock is ransomware that prevents users from accessing the infected machine's Desktop; it then demands payment, supposedly for either possession of illegal material or usage of illegal software.</ttp:Description>" +
				"</ttp:Malware_Instance>" +
				"</ttp:Malware>" +
				"</ttp:Behavior>" +
				"<ttp:Victim_Targeting>" +
				"<ttp:Targeted_Systems>HTML</ttp:Targeted_Systems>" +
				"</ttp:Victim_Targeting>" +
				"<ttp:Information_Source>" +
				"<stixCommon:Contributing_Sources>" +
				"<stixCommon:Source>" +
				"<stixCommon:Identity>" +
				"<stixCommon:Name>F-Secure</stixCommon:Name>" +
				"</stixCommon:Identity>" +
				"</stixCommon:Source>" +
				"</stixCommon:Contributing_Sources>" +
				"</ttp:Information_Source>" +
				"</stixCommon:TTP>" +
				"</indicator:Indicated_TTP>" +
				"<indicator:Suggested_COAs>" +
				"<indicator:Suggested_COA>" +
				"<stixCommon:Course_Of_Action xsi:type=\"coa:CourseOfActionType\">" +
				"<coa:Description>F-Secure</coa:Description>" +
				"</stixCommon:Course_Of_Action>" +
				"</indicator:Suggested_COA>" +
				"</indicator:Suggested_COAs>" +
				"</stix:Indicator>" +
				"</stix:Indicators>" +
				"</stix:STIX_Package>";

			
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			assertEquals(expectedPackage.getIndicators(), fsecurePackage.getIndicators());

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
			
			FSecureToStixExtractor fsecureExt = new FSecureToStixExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println(fsecurePackage.toXMLString(true));
			assertTrue(fsecureExt.validate(fsecurePackage));
			
			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
				"<stix:STIX_Package " +
				"id=\"stucco:F-Secure-585ca579-8edf-47c5-96f7-6a393c2f67cc\" " +
				"timestamp=\"2015-07-07T19:20:01.991Z\" " +
				"xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">" +
				"<stix:STIX_Header>" +
				"<stix:Title>F-Secure</stix:Title>" +
				"</stix:STIX_Header>" +
				"<stix:Indicators>" +
				"<stix:Indicator " +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\">" +
				"<indicator:Type>Malware</indicator:Type>" +
				"<indicator:Alternative_ID>DroidKungFu</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>DroidKungFu.C</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>Trojan:Android/DroidKungFu.C</indicator:Alternative_ID>" +
				"<indicator:Observable/>" +
				"<indicator:Indicated_TTP>" +
				"<stixCommon:TTP xsi:type=\"ttp:TTPType\">" +
				"<ttp:Behavior>" +
				"<ttp:Attack_Patterns>" +
				"<ttp:Attack_Pattern>" +
				"<ttp:Title>Details</ttp:Title>" +
				"<ttp:Description>Trojan:Android/DroidKungFu.C are distributed on unauthorized Android app sites as trojanized versions of legitimate applications.</ttp:Description>" +
				"</ttp:Attack_Pattern>" +
				"</ttp:Attack_Patterns>" +
				"<ttp:Malware>" +
				"<ttp:Malware_Instance>" +
                                "<ttp:Type>Malware</ttp:Type>" +
                                "<ttp:Type>Trojan</ttp:Type>" +
                                "<ttp:Name>Trojan:Android/DroidKungFu.C</ttp:Name>" +
				"<ttp:Description>Trojan:Android/DroidKungFu.C forwards confidential details to a remote server.</ttp:Description>" +
				"</ttp:Malware_Instance>" +
				"</ttp:Malware>" +
				"</ttp:Behavior>" +
				"<ttp:Victim_Targeting>" +
				"<ttp:Targeted_Systems>Android</ttp:Targeted_Systems>" +
				"</ttp:Victim_Targeting>" +
				"<ttp:Information_Source>" +
				"<stixCommon:Contributing_Sources>" +
				"<stixCommon:Source>" +
				"<stixCommon:Identity>" +
				"<stixCommon:Name>F-Secure</stixCommon:Name>" +
				"</stixCommon:Identity>" +
				"</stixCommon:Source>" +
				"</stixCommon:Contributing_Sources>" +
				"</ttp:Information_Source>" +
				"</stixCommon:TTP>" +
				"</indicator:Indicated_TTP>" +
				"</stix:Indicator>" +
				"</stix:Indicators>" +
				"</stix:STIX_Package>";

			
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			assertEquals(expectedPackage.getIndicators(), fsecurePackage.getIndicators());

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
			
			FSecureToStixExtractor fsecureExt = new FSecureToStixExtractor(pageContent);
			STIXPackage fsecurePackage = fsecureExt.getStixPackage();
		    	
			System.out.println(fsecurePackage.toXMLString(true));
			assertTrue(fsecureExt.validate(fsecurePackage));

			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
				"<stix:STIX_Package " +
				"id=\"stucco:F-Secure-dba72fa3-bd0b-4744-b563-36f62146ee04\" " +
				"timestamp=\"2015-07-07T19:28:33.777Z\" " +
				"xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">" +
				"<stix:STIX_Header>" +
				"<stix:Title>F-Secure</stix:Title>" +
				"</stix:STIX_Header>" +
				"<stix:Indicators>" +
				"<stix:Indicator " +
				"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\">" +
				"<indicator:Type>Malware</indicator:Type>" +
				"<indicator:Alternative_ID>BASH/QHost.WB</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>QHost</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>QHost.WB</indicator:Alternative_ID>" +
				"<indicator:Alternative_ID>Trojan:BASH/QHost.WB</indicator:Alternative_ID>" +
				"<indicator:Observable/>" +
				"<indicator:Indicated_TTP>" +
				"<stixCommon:TTP xsi:type=\"ttp:TTPType\">" +
				"<ttp:Behavior>" +
				"<ttp:Attack_Patterns>" +
				"<ttp:Attack_Pattern>" +
				"<ttp:Title>Details</ttp:Title>" +
				"<ttp:Description>Trojan:BASH/QHost.WB poses as a FlashPlayer installer called FlashPlayer.pkg:</ttp:Description>" +
				"</ttp:Attack_Pattern>" +
				"</ttp:Attack_Patterns>" +
				"<ttp:Malware>" +
				"<ttp:Malware_Instance>" +
				"<ttp:Type>Malware</ttp:Type>" +
				"<ttp:Type>Trojan</ttp:Type>" +
				"<ttp:Name>Trojan:BASH/QHost.WB</ttp:Name>" +
				"<ttp:Description>Trojan:BASH/QHost.WB hijacks web traffic by modifying the hosts file.</ttp:Description>" +
				"</ttp:Malware_Instance>" +
				"</ttp:Malware>" +
				"</ttp:Behavior>" +
				"<ttp:Victim_Targeting>" +
				"<ttp:Targeted_Systems>BASH</ttp:Targeted_Systems>" +
				"</ttp:Victim_Targeting>" +
				"<ttp:Information_Source>" +
				"<stixCommon:Contributing_Sources>" +
				"<stixCommon:Source>" +
				"<stixCommon:Identity>" +
				"<stixCommon:Name>F-Secure</stixCommon:Name>" +
				"</stixCommon:Identity>" +
				"</stixCommon:Source>" +
				"</stixCommon:Contributing_Sources>" +
				"</ttp:Information_Source>" +
				"</stixCommon:TTP>" +
				"</indicator:Indicated_TTP>" +
				"</stix:Indicator>" +
				"</stix:Indicators>" +
				"</stix:STIX_Package>";

			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			assertEquals(expectedPackage.getIndicators(), fsecurePackage.getIndicators());

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

}
