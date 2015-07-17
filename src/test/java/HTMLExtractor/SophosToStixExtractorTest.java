package HTMLExtractor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;
import java.util.LinkedHashSet;

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
import org.json.XML;
import org.json.JSONException;
			
import javax.xml.bind.JAXBElement;
	
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.MalwareType;
import org.mitre.stix.ttp_1.MalwareInstanceType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.indicator_2.ValidTimeType;
import org.mitre.stix.ttp_1.VictimTargetingType;
import org.mitre.stix.ttp_1.ResourceType;
import org.mitre.stix.ttp_1.ToolsType;
import org.mitre.stix.common_1.ToolInformationType;
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
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.cybox.objects.DNSRecord;
import org.mitre.cybox.objects.URIObjectType;
import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.CustomPropertiesType;
import org.mitre.cybox.common_2.Property;
import org.mitre.cybox.common_2.MeasureSourceType;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.cybox_2.AssociatedObjectType;
import org.mitre.cybox.cybox_2.AssociatedObjectsType;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.cybox.cybox_2.ActionsType;
import org.mitre.cybox.cybox_2.ActionType;
import org.mitre.cybox.objects.ProcessObjectType;
import org.mitre.cybox.objects.WindowsRegistryKey;
import org.mitre.cybox.common_2.HashListType;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.SimpleHashValueType;
import org.mitre.cybox.common_2.UnsignedLongObjectPropertyType;					
import org.mitre.cybox.cybox_2.Event;
import org.mitre.cybox.common_2.DigitalSignaturesType;
import org.mitre.cybox.cybox_2.ObservableCompositionType;	
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;												
import org.mitre.cybox.cybox_2.FrequencyType;
import org.mitre.maec.xmlschema.maec_bundle_4.MalwareActionType;
import org.mitre.cybox.objects.Port;
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;
import org.mitre.cybox.objects.DNSRecord;
import org.mitre.cybox.common_2.DatatypeEnum;
import org.mitre.cybox.objects.Custom;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;

import org.mitre.stix.indicator_2.Indicator;

import HTMLExtractor.SophosToStixExtractor;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit test for Sophos extractor.
 */
public class SophosToStixExtractorTest{
	
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
					
	private JSONArray removeEmptyObjects (JSONArray jsonArray)	{
							
		if (jsonArray == null | jsonArray.length() == 0) return null;		
								
		for (int i = 0; i < jsonArray.length(); i++)	{
									
			if (jsonArray.get(i) instanceof JSONObject)	{
				if (removeEmptyFields(jsonArray.getJSONObject(i)) == null)	{
					jsonArray.remove(i);
					i--;
				}
			}
										
			if (jsonArray.get(i) instanceof JSONArray)
				removeEmptyObjects(jsonArray.getJSONArray(i));
		}
		return jsonArray;
	}

	private JSONObject removeEmptyFields (JSONObject jsonObject)	{
			
		Iterator<String> keys = jsonObject.keys();
		int count = 0;
		while(keys.hasNext())	{
			count++;
			String key = keys.next();

			if (jsonObject.get(key) instanceof JSONObject)	{
				if (jsonObject.isNull(key))	{
					keys.remove();
					count--;
				}
				else removeEmptyFields(jsonObject.getJSONObject(key));	
			}
			else if (jsonObject.get(key) instanceof JSONArray)	{
				if (jsonObject.getJSONArray(key).length() == 0)	{
					keys.remove();
					count--;
				}
				else	{
					for (int i = 0; i < jsonObject.getJSONArray(key).length(); i++)	
						removeEmptyObjects(jsonObject.getJSONArray(key));
				}										
			}
			else	{													
				if (jsonObject.isNull(key) | jsonObject.get(key).toString().replaceAll("\\s","").length() == 0)	{
					keys.remove();
					count--;
				}
			}
		}
		if (count == 0) {
			return null;
		}
		return jsonObject;
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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
								
			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-29695616-7d3e-473e-b4c4-fafb03b58c09\" " +
				"    timestamp=\"2015-07-16T15:48:19.755Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator timestamp=\"2008-11-26T09:13:32.000-05:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Alternative_ID>Worm:Win32/Conficker.gen!A</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>W32/Conficker.worm</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Worm:W32/Downadup</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>WORM_DOWNAD.AD</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Mal/Conficker-A</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Net-Worm.Win32.Kido</indicator:Alternative_ID> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1227708812000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1227708812000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Major Outbreak</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Malicious behavior</ttp:Type> " +
				"                                <ttp:Name>Mal/Conficker-A</ttp:Name> " +
				"                                <ttp:Description>Mal/Conficker-A</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";

				
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			
			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));
				
			//adding extra type field to the indicator							
			IndicatorsType indicators = expectedPackage.getIndicators();
			List<IndicatorBaseType> indicatorsList = indicators.getIndicators();
			Indicator indicator = (Indicator)indicatorsList.get(0);				
			indicator
				.withTypes(new ControlledVocabularyStringType()
					.withValue("Extra Type"));
			
			assertFalse(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));
				
		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}  //catch (JSONException e) {
    		//	e.printStackTrace();
  	//	}
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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-cd2e9c29-b085-47cf-b78a-c886e5b0721c\" " +
				"    timestamp=\"2015-07-16T17:12:40.190Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator timestamp=\"2010-09-15T19:26:33.000-04:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>text/html</FileObj:File_Name> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/octet-stream</FileObj:File_Name> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1284593193000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1284593193000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/FBJack-A</ttp:Name> " +
				"                                <ttp:Description>Troj/FBJack-A</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";
								
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
											
			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));

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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			String expectedVerts =								
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-d7c76251-1f8a-4829-b04a-cf61bdf5933b\" " +
				"    timestamp=\"2015-07-16T16:36:55.725Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">0</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">0</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/Agent-DP</ttp:Name> " +
				"                                <ttp:Description>Troj/Agent-DP</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";
		    						
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);

			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));

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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-ea72cf9e-c36f-4065-acc5-732293f5b02f\" " +
				"    timestamp=\"2015-07-16T18:37:11.754Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " +
				"    xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:maecBundle=\"http://maec.mitre.org/XMLSchema/maec-bundle-4\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>80</cybox:Description> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>franciz-industries.biz, port 80</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>franciz-industries.biz:80</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>DNSName</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"DNSRecordObj:DNSRecordObjectType\"> " +
				"                        <DNSRecordObj:Description>franciz-industries.biz</DNSRecordObj:Description> " +
				"                        <DNSRecordObj:Domain_Name> " +
				"                            <URIObj:Value>franciz-industries.biz</URIObj:Value> " +
				"                        </DNSRecordObj:Domain_Name> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>80</cybox:Description> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>www.google.com, port 80</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>www.google.com:80</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>DNSName</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"DNSRecordObj:DNSRecordObjectType\"> " +
				"                        <DNSRecordObj:Description>www.google.com</DNSRecordObj:Description> " +
				"                        <DNSRecordObj:Domain_Name> " +
				"                            <URIObj:Value>www.google.com</URIObj:Value> " +
				"                        </DNSRecordObj:Domain_Name> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>80</cybox:Description> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>www.google.ie, port 80</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>www.google.ie:80</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>DNSName</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"DNSRecordObj:DNSRecordObjectType\"> " +
				"                        <DNSRecordObj:Description>www.google.ie</DNSRecordObj:Description> " +
				"                        <DNSRecordObj:Domain_Name> " +
				"                            <URIObj:Value>www.google.ie</URIObj:Value> " +
				"                        </DNSRecordObj:Domain_Name> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator timestamp=\"2014-08-16T00:13:47.000-04:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Alternative_ID>Gen:Variant.Graftor.150885</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Troj/Zbot-ITY</indicator:Alternative_ID> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>Windows executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>8bff3c73c92314a7d094a0d024cf57a722b0b198</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>599990d8fa3d211b0b775d82dd939526</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>a5597354</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>Windows executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>9017bd0da5f94f4ba899e5d990c8c4f4792d6876</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>ca2fe00295a6255ced2778fb9f43146f</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>a801cd75</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1407888000000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1408162427000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Event> " +
				"                            <cybox:Event> " +
				"                                <cybox:Actions> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created files</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>c:\\Documents and Settings\\test user\\Application Data\\Poce\\anyn.ezo</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>c:\\Documents and Settings\\test user\\Application Data\\Veufno\\buerx.exe</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Modified</cybox:Type> " +
				"                                    <cybox:Description>Modified files</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Folders.dbx</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Inbox.dbx</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>%PROFILE%\\Local Settings\\Application Data\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Microsoft\\Outlook Express\\Offline.dbx</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created registry keys</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Identities</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Dyxol</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Internet Explorer\\Privacy</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Modified</cybox:Type> " +
				"                                    <cybox:Description>Modified registry keys</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Identities\\{E2564744-A8ED-497D-924B-A548B20CA034}\\Software\\Microsoft\\Outlook Express\\5.0</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\UnreadMail\\user@example.com</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created processes</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\tasklist.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\cmd.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\hostname.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\ipconfig.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\Documents and Settings\\test user\\application data\\veufno\\buerx.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                </cybox:Actions> " +
				"                            </cybox:Event> " +
				"                        </cybox:Event> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/Zbot-ITY</ttp:Name> " +
				"                                <ttp:Description>Troj/Zbot-ITY</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Resources> " +
				"                        <ttp:Tools> " +
				"                            <ttp:Tool> " +
				"                                <cyboxCommon:Name>http://www.google.com/webhp</cyboxCommon:Name> " +
				"                                <cyboxCommon:Type>url</cyboxCommon:Type> " +
				"                            </ttp:Tool> " +
				"                            <ttp:Tool> " +
				"                                <cyboxCommon:Name>http://www.google.ie/webhp</cyboxCommon:Name> " +
				"                                <cyboxCommon:Type>url</cyboxCommon:Type> " +
				"                            </ttp:Tool> " +
				"                        </ttp:Tools> " +
				"                    </ttp:Resources> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";

			
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);

			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));

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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-2952b0ce-42fd-447a-b14e-4f8adcd2e962\" " +
				"    timestamp=\"2015-07-16T18:27:40.138Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:maecBundle=\"http://maec.mitre.org/XMLSchema/maec-bundle-4\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator timestamp=\"2010-10-02T06:41:58.000-04:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Alternative_ID>Trojan-Spy.Win32.Zbot.aput</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Troj/Zbot-AAA</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>TR/Spy.ZBot.aput</indicator:Alternative_ID> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/x-ms-dos-executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>5d012753322151c9d24bf45b98c35336225f383f</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>c4e28e07ebb3a69fd165977f0331f1c5</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>ab4dcfbd</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/x-ms-dos-executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>b1005a9483866a45046a9b9d9bea09d39b29dcde</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>15eabc798ddf5542afec25946a00e987</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>a32246d3</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/x-ms-dos-executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>b76ad9b1c6e01e41b8e05ab9be0617fff06fad98</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>d9dfa48afeb08f6e67fb8b2254a76870</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>2f6c8b97</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1285718400000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1286016118000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Event> " +
				"                            <cybox:Event> " +
				"                                <cybox:Actions> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created files</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>c:\\Documents and Settings\\test user\\Application Data\\Neceq\\esbo.exe</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created processes</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\cmd.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                </cybox:Actions> " +
				"                            </cybox:Event> " +
				"                        </cybox:Event> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/Zbot-AAA</ttp:Name> " +
				"                                <ttp:Description>Troj/Zbot-AAA</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";


			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);

			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));

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
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
		    	
			String expectedVerts = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-323f1679-3db6-484d-aab9-91a4e1f8c1dc\" " +
				"    timestamp=\"2015-07-16T16:43:02.193Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:maecBundle=\"http://maec.mitre.org/XMLSchema/maec-bundle-4\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>8080</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>176.123.0.160, port 8080</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>176.123.0.160:8080</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>ip</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>176.123.0.160</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>176.123.0.160</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>8080</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>195.5.208.87, port 8080</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>195.5.208.87:8080</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>ip</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>195.5.208.87</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>195.5.208.87</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>8080</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>195.65.173.133, port 8080</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>195.65.173.133:8080</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>ip</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>195.65.173.133</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>195.65.173.133</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>8080</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>222.124.143.12, port 8080</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>222.124.143.12:8080</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>ip</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>222.124.143.12</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>222.124.143.12</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>8080</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>46.105.117.13, port 8080</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>46.105.117.13:8080</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>ip</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>46.105.117.13</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>46.105.117.13</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator timestamp=\"2014-08-18T16:16:07.000-04:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Alternative_ID>TR/Crypt.XPACK.Gen7</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>Troj/Weelsof-FG</indicator:Alternative_ID> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/x-ms-dos-executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>b2a166c4d67f324a6ae87e142040f932ccbb596d</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>cc3223eca31b00692fa49e63ac88139b</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>3a5172d0</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1408320000000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1408392967000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Event> " +
				"                            <cybox:Event> " +
				"                                <cybox:Actions> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created files</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>c:\\Documents and Settings\\test user\\Local Settings\\Application Data\\nfdenoin.exe</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created registry keys</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\fopnellh</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created processes</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\svchost.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                </cybox:Actions> " +
				"                            </cybox:Event> " +
				"                        </cybox:Event> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/Weelsof-FG</ttp:Name> " +
				"                                <ttp:Description>Troj/Weelsof-FG</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";   	
			
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			
			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));
							
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
			System.out.println("---------------> test ");
			Map<String,String> pageContent = loadContent(entryName, localMode);
			summary = pageContent.get("summary");
			details = pageContent.get("details");
			
			SophosToStixExtractor sophosExtractor = new SophosToStixExtractor(summary, details);
			STIXPackage receivedPackage = sophosExtractor.getStixPackage();
			
			String expectedVerts =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Sophos-2451ee8d-070b-4f52-89d1-0577043f157d\" " +
				"    timestamp=\"2015-07-16T16:16:42.542Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:CustomObj=\"http://cybox.mitre.org/objects#CustomObject-1\" " +
				"    xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " +
				"    xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:maecBundle=\"http://maec.mitre.org/XMLSchema/maec-bundle-4\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Sophos</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Port</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>80</cybox:Description> " +
				"                    <cybox:Properties xsi:type=\"PortObj:PortObjectType\"> " +
				"                        <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Address</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Description>riseandshine.favcc1.com, port 80</cybox:Description> " +
				"                    <cybox:Properties category=\"ipv4-addr\" xsi:type=\"AddressObj:AddressObjectType\"> " +
				"                        <AddressObj:Address_Value>riseandshine.favcc1.com:80</AddressObj:Address_Value> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>DNSName</indicator:Type> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Source> " +
				"                    <cyboxCommon:Information_Source_Type>Sophos</cyboxCommon:Information_Source_Type> " +
				"                </cybox:Observable_Source> " +
				"                <cybox:Object> " +
				"                    <cybox:Properties xsi:type=\"DNSRecordObj:DNSRecordObjectType\"> " +
				"                        <DNSRecordObj:Description>riseandshine.favcc1.com</DNSRecordObj:Description> " +
				"                        <DNSRecordObj:Domain_Name> " +
				"                            <URIObj:Value>riseandshine.favcc1.com</URIObj:Value> " +
				"                        </DNSRecordObj:Domain_Name> " +
				"                    </cybox:Properties> " +
				"                </cybox:Object> " +
				"            </indicator:Observable> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator timestamp=\"2014-08-18T16:16:07.000-04:00\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Type>Malware</indicator:Type> " +
				"            <indicator:Alternative_ID>Troj/MSIL-ACB</indicator:Alternative_ID> " +
				"            <indicator:Alternative_ID>TR/Dropper.MSIL.Gen8</indicator:Alternative_ID> " +
				"            <indicator:Observable> " +
				"                <cybox:Observable_Composition operator=\"AND\"> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                <FileObj:File_Name>application/x-ms-dos-executable</FileObj:File_Name> " +
				"                                <FileObj:Hashes> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>SHA-1</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>4122be8402684403e480aaf5b37caf3b727d8077</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>c5579ab457536d2fbd48e0a3bc6dc458</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Hash> " +
				"                                    <cyboxCommon:Type>CRC-32</cyboxCommon:Type> " +
				"                                    <cyboxCommon:Simple_Hash_Value>3311bf61</cyboxCommon:Simple_Hash_Value> " +
				"                                    </cyboxCommon:Hash> " +
				"                                </FileObj:Hashes> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Object> " +
				"                            <cybox:Properties xsi:type=\"CustomObj:CustomObjectType\"> " +
				"                                <cyboxCommon:Custom_Properties> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"DiscoveredDate\">1408320000000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"unsignedLong\" name=\"ModifiedDate\">1408392967000</cyboxCommon:Property> " +
				"                                    <cyboxCommon:Property " +
				"                                    datatype=\"string\" name=\"Prevalence\">Small Number of Reports</cyboxCommon:Property> " +
				"                                </cyboxCommon:Custom_Properties> " +
				"                            </cybox:Properties> " +
				"                        </cybox:Object> " +
				"                    </cybox:Observable> " +
				"                    <cybox:Observable> " +
				"                        <cybox:Event> " +
				"                            <cybox:Event> " +
				"                                <cybox:Actions> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created files</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
				"                                    <FileObj:File_Name>c:\\Documents and Settings\\test user\\Local Settings\\Temp\\141781.bat</FileObj:File_Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created registry keys</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
				"                                    <WinRegistryKeyObj:Key>HKCU\\Software\\WinRAR</WinRegistryKeyObj:Key> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                    <cybox:Action xsi:type=\"maecBundle:MalwareActionType\"> " +
				"                                    <cybox:Type>Created</cybox:Type> " +
				"                                    <cybox:Description>Created processes</cybox:Description> " +
				"                                    <cybox:Associated_Objects> " +
				"                                    <cybox:Associated_Object> " +
				"                                    <cybox:Properties xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                                    <ProcessObj:Name>c:\\windows\\system32\\cmd.exe</ProcessObj:Name> " +
				"                                    </cybox:Properties> " +
				"                                    </cybox:Associated_Object> " +
				"                                    </cybox:Associated_Objects> " +
				"                                    </cybox:Action> " +
				"                                </cybox:Actions> " +
				"                            </cybox:Event> " +
				"                        </cybox:Event> " +
				"                    </cybox:Observable> " +
				"                </cybox:Observable_Composition> " +
				"            </indicator:Observable> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP xsi:type=\"ttp:TTPType\"> " +
				"                    <ttp:Behavior> " +
				"                        <ttp:Malware> " +
				"                            <ttp:Malware_Instance> " +
				"                                <ttp:Type>Trojan</ttp:Type> " +
				"                                <ttp:Name>Troj/MSIL-ACB</ttp:Name> " +
				"                                <ttp:Description>Troj/MSIL-ACB</ttp:Description> " +
				"                            </ttp:Malware_Instance> " +
				"                        </ttp:Malware> " +
				"                    </ttp:Behavior> " +
				"                    <ttp:Resources> " +
				"                        <ttp:Tools> " +
				"                            <ttp:Tool> " +
				"                                <cyboxCommon:Name>http://riseandshine.favcc1.com/gate.php</cyboxCommon:Name> " +
				"                                <cyboxCommon:Type>url</cyboxCommon:Type> " +
				"                            </ttp:Tool> " +
				"                        </ttp:Tools> " +
				"                    </ttp:Resources> " +
				"                    <ttp:Victim_Targeting> " +
				"                        <ttp:Targeted_Systems>Windows</ttp:Targeted_Systems> " +
				"                    </ttp:Victim_Targeting> " +
				"                    <ttp:Information_Source> " +
				"                        <stixCommon:Identity> " +
				"                            <stixCommon:Name>Sophos</stixCommon:Name> " +
				"                        </stixCommon:Identity> " +
				"                    </ttp:Information_Source> " +
				"                </stixCommon:TTP> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";
							
			STIXPackage expectedPackage = new STIXPackage().fromXMLString(expectedVerts);
			
			assertTrue(sophosExtractor.validate(receivedPackage));
			assertTrue(HTMLExtractor.compareStixPackages(receivedPackage, expectedPackage));

		} catch (IOException e) {
			e.printStackTrace();
			fail("IOException");
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}
