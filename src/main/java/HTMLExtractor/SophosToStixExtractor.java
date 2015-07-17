package HTMLExtractor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;
import java.util.LinkedHashSet;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

import org.xml.sax.SAXException;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;
import javax.xml.datatype.DatatypeConfigurationException;
			
public class SophosToStixExtractor extends HTMLExtractor{
	
	private STIXPackage stixPackage;

	private JSONObject graph;						
	private static final Logger logger = LoggerFactory.getLogger(SophosToStixExtractor.class);

	public SophosToStixExtractor(String summary, String details){
		stixPackage = extract(summary, details);
	}
	
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time, "dd MMM yyyy hh:mm:ss (z)");
	}
	
	private long convertShortTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "yyyy-MM-dd (z)");
	}
	
	private STIXPackage extract(String summary, String details){
	
		try	{

		Indicator indicator = new Indicator();
		TTP ttp = new TTP();				
		ObservableCompositionType observableComposition = new ObservableCompositionType().withOperator(OperatorTypeEnum.AND);
		MalwareInstanceType malware = new MalwareInstanceType();
		IndicatorsType indicators = new IndicatorsType();
		InformationSourceType source = new InformationSourceType();
		Observables observables = new Observables();
		GregorianCalendar calendar = new GregorianCalendar();
		XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
			new GregorianCalendar(TimeZone.getTimeZone("UTC")));
		stixPackage = new STIXPackage()				
 			.withSTIXHeader(new STIXHeaderType().
				withTitle("Sophos")) 
			.withTimestamp(now)
 			.withId(new QName("stucco", "Sophos-" + UUID.randomUUID().toString(), "stucco"));
		Property discoveredDateTime = new Property().withName("DiscoveredDate").withValue("0").withDatatype(DatatypeEnum.UNSIGNED_LONG);
		Property modifiedDateTime = new Property().withName("ModifiedDate").withValue("0").withDatatype(DatatypeEnum.UNSIGNED_LONG);
		Property prevalence = new Property().withName("Prevalence").withDatatype(DatatypeEnum.STRING);
		long signatureDate = 0L; 		//would be a timestamp attribute in ttp

		//process the "summary" page
		Document doc = Jsoup.parse(summary);
		Element content = doc.getElementsByClass("tertiaryBump").first();
		logger.debug(content.html());
		
		//get the title, set up name & other known fields
		Element titleDiv = content.getElementsByClass("marqTitle").first();
		logger.debug(titleDiv.html());
		String vertexName = titleDiv.getElementsByTag("h1").first().text();
		logger.info("Name: {}", vertexName);
		
		Element rowOne = titleDiv.getElementsByTag("tr").first();
		String addedDate = rowOne.child(3).text();
		if(!addedDate.equals("")){//some don't list dates, not sure why
											//signedDAte	
			discoveredDateTime						//discoveredDate
				.setValue(Long.toString(convertTimestamp(addedDate)));	//has to be a string, or toXMLString() would not work
			signatureDate = convertTimestamp(addedDate);
			calendar.setTimeInMillis(convertTimestamp(addedDate));
			indicator											
				.withTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar));
			observableComposition.setOperator(OperatorTypeEnum.AND);
		}			
		
		Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
		String type = rowTwo.child(1).text();
											
		List<ControlledVocabularyStringType> types = new ArrayList<ControlledVocabularyStringType>();
		types.add(new ControlledVocabularyStringType()
			.withValue(type));
																			
		String modifiedDate = rowTwo.child(3).text();
		if(!modifiedDate.equals(""))	{
			modifiedDateTime 
				.setValue(Long.toString(convertTimestamp(addedDate)));	//modifiedDAte
		}
													//prevalence
		Element rowThree = titleDiv.getElementsByTag("tr").get(2);
		String prev = rowThree.child(1).getElementsByTag("img").first().attr("alt");
		logger.info("Prevalence: {}", prev);
		prevalence 
			.withValue(prev);

		//handle secondary div
		Element secondaryDiv = doc.getElementsByClass("secondaryContent").first();
		logger.debug(secondaryDiv.html());
		Elements aliasItems = secondaryDiv.getElementsByClass("aliases");
		TreeSet<String> aliasSet = new TreeSet<String>();
		
		if(aliasItems != null && aliasItems.size() > 0){ //some don't have any listed.
			aliasItems = aliasItems.first().children();
			logger.debug(aliasItems.outerHtml());
			for(int i=0; i<aliasItems.size(); i++){
				aliasSet.add(aliasItems.get(i).text());
			}
			aliasSet.add(vertexName);
			//TODO: how best to handle aliases in the long term?
			logger.info("Found {} items in aliasList:", aliasSet.size());
			List<String> list = new ArrayList<String>(aliasSet);
			for(int i=0; i<list.size(); i++){
				logger.info(list.get(i));
			}
		}
		Elements h3s = secondaryDiv.getElementsByTag("h3");
		Element affectedHeading = null;
		for(int i=0; i<h3s.size(); i++){
			if(h3s.get(i).text().equals("Affected Operating Systems")){
				affectedHeading = h3s.get(i);
				break;
			}
		}
																//platform
		String platformName = affectedHeading.nextElementSibling().getElementsByTag("img").first().attr("alt");
		if(affectedHeading != null){
			logger.info("Platform: {}", platformName);
		}
		
		////////////////////////////////////
		//process the "details" page
		doc = Jsoup.parse(details);
		content = doc.getElementsByClass("threatDetail").first();
		
		//handle the "File Information" tables
		Elements h4headings = content.getElementsByTag("h4");
		Element curr, nextSibling;
		Map<String,String> currTableContents;
		TreeSet<String> size = new TreeSet<String>();
		long firstSeen;
		boolean runtimeAnalysisFound = false;
						
		Set<Observable> set = new LinkedHashSet<Observable>();

		for(int i=0; i<h4headings.size(); i++){
			curr = h4headings.get(i);
			nextSibling = curr.nextElementSibling();
			if(curr.text().equals("File Information") && nextSibling.tagName().equals("dl")){
				logger.debug("Found a file info table: \n{}", nextSibling.html());
				currTableContents = dlToMap(nextSibling);  
				if(currTableContents == null){
					logger.error("Could not parse table contents! (file info)");
				}else{
					FileObjectType file = new FileObjectType();
					List<HashType> hashes = new ArrayList<HashType>();
					firstSeen = 0;

					logger.info("Extracted map from file info table: {}", currTableContents);
					if(currTableContents.containsKey("Size")){
						size.add(currTableContents.get("Size"));
					}
					if(currTableContents.containsKey("SHA-1")){
						hashes.add(getHash("SHA-1", currTableContents.get("SHA-1")));
					}
					if(currTableContents.containsKey("MD5")){
						hashes.add(getHash("MD5", currTableContents.get("MD5")));
					}					
					if(currTableContents.containsKey("CRC-32")){
						hashes.add(getHash("CRC-32", currTableContents.get("CRC-32")));
					}						
					if(currTableContents.containsKey("File type")){
			
						file
							.withFileName(new StringObjectPropertyType()
								.withValue(currTableContents.get("File type")));
					}
					if(currTableContents.containsKey("First seen")){
			
						firstSeen = convertShortTimestamp(currTableContents.get("First seen"));
						//have to do all those comvertions, or toXMLString() would not work ....	
						if(firstSeen < Long.parseLong(discoveredDateTime.getValue().toString())){
							discoveredDateTime.setValue(Long.toString(firstSeen));
						}
					}	
					if (!hashes.isEmpty())
						file
							.withHashes(new HashListType()
								.withHashes(hashes));
					set.add(new Observable().withObject(new ObjectType().withProperties(file)));
				}
			}else if(curr.text().equals("Runtime Analysis")){
				//could do this here, but it's kind of complicated, better to separate it out...
				runtimeAnalysisFound = true;
				logger.info("Runtime Analysis section found, handling later...");
			}else if(curr.text().equals("Other vendor detection") && nextSibling.tagName().equals("dl")){
				currTableContents = dlToMap(nextSibling); 
				if(currTableContents == null){
					logger.error("Could not parse table contents! (other vendor detection)");
				}else{
					logger.info("Extracted map from 'other vendor detection table: {}", currTableContents);
					Set<String> keys = currTableContents.keySet();
					Iterator<String> keysIter = keys.iterator();
					while(keysIter.hasNext()){
						aliasSet.add(currTableContents.get(keysIter.next()));
					}
					logger.info("  now know aliases: {}", aliasSet);
				}
			}else{
				logger.warn("Unexpected H4 Found: {}", curr.text());
			}
		}
		
		if (!aliasSet.isEmpty())
			indicator
				.withAlternativeIDs(aliasSet);
		
		if (!set.isEmpty())
			observableComposition
				.withObservables(set);
		
		observableComposition
			.withObservables(new Observable()			//list
				.withObject(new ObjectType()
					.withProperties(new Custom()
						.withCustomProperties(new CustomPropertiesType()
							.withProperties(discoveredDateTime)
							.withProperties(modifiedDateTime)
							.withProperties(prevalence)))));
											
		
		//handle the "Runtime Analysis" sections...
		if(runtimeAnalysisFound){
			Element nextNextSibling;
			Set<String> ipConnections = new LinkedHashSet<String>();
			Set<String> dnsRequests = new LinkedHashSet<String>();
																		
			Set<AssociatedObjectType> createdFiles = new LinkedHashSet<AssociatedObjectType>();;
			Set<AssociatedObjectType> modifiedFiles = new LinkedHashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> createdProcesses = new LinkedHashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> createdRegistryKeys = new LinkedHashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> modifiedRegistryKeys = new LinkedHashSet<AssociatedObjectType>();
			
			for(int i=0; i<h4headings.size(); i++){
				curr = h4headings.get(i);
				nextSibling = curr.nextElementSibling();
				nextNextSibling = nextSibling.nextElementSibling();
				Set<String> newItems;
				if(curr.text().equals("Runtime Analysis")){
					logger.info("'Runtime Analysis' section found");
					while(nextSibling != null && nextSibling.tagName().equals("h5") && 
							nextNextSibling != null && nextNextSibling.tagName().equals("ul")){
						if(nextSibling.text().equals("Dropped Files")){
							//TODO save other fields?  MD5 & etc?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							createdFiles.addAll(getFiles(newItems));
							logger.info("Dropped Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Copies Itself To")){
							//TODO save other fields?  MD5 & etc?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							createdFiles.addAll(getFiles(newItems));
							logger.info("Copies Itself To: {}", newItems);
						}
				 		else if(nextSibling.text().equals("Modified Files")){
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							modifiedFiles.addAll(getFiles(newItems));
							logger.info("Modified Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Created")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							createdRegistryKeys.addAll(getRegistryKeys(newItems));
							logger.info("Registry Keys Created: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Modified")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							modifiedRegistryKeys.addAll(getRegistryKeys(newItems));
							logger.info("Registry Keys Modified: {}", newItems);
						}
						else if(nextSibling.text().equals("Processes Created")){
							newItems = ulToSet(nextNextSibling);
							createdProcesses.addAll(getProcesses(newItems));
							logger.info("Processes Created: {}", newItems);
						}
						else if(nextSibling.text().equals("IP Connections")){
							newItems = ulToSet(nextNextSibling);
							ipConnections.addAll(newItems);
							logger.info("IP Connections: {}", newItems);
						}
						else if(nextSibling.text().equals("DNS Requests")){
							newItems = ulToSet(nextNextSibling);
							dnsRequests.addAll(newItems);
							logger.info("DNS Requests: {}", newItems);
						}
						else if(nextSibling.text().equals("HTTP Requests")){
							newItems = ulToSet(nextNextSibling);
							ttp
								.withResources(new ResourceType()
									.withTools(getTools("url", newItems)));
							logger.info("HTTP Requests: {}", newItems);
						}
						else{
							logger.info("Unknown! {}:\n{}", nextSibling.text(), nextNextSibling.outerHtml());
						}
						nextSibling = nextNextSibling.nextElementSibling();
						if(nextSibling != null) nextNextSibling = nextSibling.nextElementSibling();
					}
				}
			}

		//	AssociatedObjectsType objects = new AssociatedObjectsType();
			ActionsType actions = new ActionsType();

			if(!createdFiles.isEmpty())	
				actions									
					.withActions(getActions("Created", "Created files", createdFiles));

			if(!modifiedFiles.isEmpty())
				actions									
					.withActions(getActions("Modified", "Modified files", modifiedFiles));
			
			if(!createdRegistryKeys.isEmpty())
				actions													
					.withActions(getActions("Created", "Created registry keys", createdRegistryKeys));
			
			if(!modifiedRegistryKeys.isEmpty())
				actions																	
					.withActions(getActions("Modified", "Modified registry keys", modifiedRegistryKeys));
				
			if(!createdProcesses.isEmpty())
				actions																	
					.withActions(getActions("Created", "Created processes", createdProcesses));
			
			observableComposition
				.withObservables(new Observable()
					.withEvent(new Event()
						.withEvents(new Event()
							.withActions(actions))));
						//moved into custom properties as prevalence ..?
						//.withFrequency(new FrequencyType()
						//	.withScale(prevalence))));
																	
			//handle IP info - build address nodes, port nodes, and any edges as needed
			if(ipConnections.size() > 0){
				for(String ip : ipConnections){
					String ipString, portString;
					int port;
					try{
						port = getPortFromURL(ip);
					}catch(Exception e){
						logger.warn("Exception when parsing port info from ip string " + ip, e);
						port = -1;
					}
					if(port != -1){
						portString = Integer.toString(port);
						if(ip.endsWith(":"+portString))
							ipString = ip.replace(":"+portString, "");
						else 
							ipString = ip;
						
						Indicator portIndicator = new Indicator()
							.withTypes(new ControlledVocabularyStringType()
								.withValue("Port"))
							.withObservable(new Observable()			//list
								.withObservableSources(new MeasureSourceType()
									.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
										.withValue("Sophos")))
								.withObject(new ObjectType()
									.withProperties(new Port()
										.withPortValue(new PositiveIntegerObjectPropertyType()
											.withValue(portString)))));
											
						indicators
							.withIndicators(portIndicator); 
						
					}else{ //shouldn't ever give -1 anyway
						logger.warn("could not find port for ip string {}", ip);
						portString = "unknown";
						ipString = ip;
					}
					
					String addressName = ipString + ":" + portString;
					String addressDesc = ipString + ", port " + portString;
					
					Indicator addressIndicator = new Indicator()
						.withTypes(new ControlledVocabularyStringType()
							.withValue("Address"))
						.withObservable(new Observable()
							.withObservableSources(new MeasureSourceType()
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("Sophos")))
							.withObject(new ObjectType()
								.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
									.withValue(addressDesc)) 
								.withProperties(new Address()
									.withAddressValue(new StringObjectPropertyType()
										.withValue(addressName))
									.withCategory(CategoryTypeEnum.IPV_4_ADDR))));
					indicators
						.withIndicators(addressIndicator); 

					Indicator ipIndicator = new Indicator()
						.withTypes(new ControlledVocabularyStringType()
							.withValue("ip"))
						.withObservable(new Observable()
							.withObservableSources(new MeasureSourceType()
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("Sophos")))
							.withObject(new ObjectType()
								.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
									.withValue(ipString)) 
								.withProperties(new Address()
									.withAddressValue(new StringObjectPropertyType()
										.withValue(ipString))
									.withCategory(CategoryTypeEnum.IPV_4_ADDR))));
					indicators
						.withIndicators(ipIndicator); 
				}
			}
			
			//if() vertex.put("dnsRequests", dnsRequests); //TODO: make vertex
			//now handle the DNS info the same way
			if(dnsRequests.size() > 0){
				for(String dns : dnsRequests){
					String dnsString, portString;
					int port;
					try{
						port = getPortFromURL(dns);
					}catch(Exception e){
						logger.warn("Exception when parsing port info from dns string " + dns, e);
						port = -1;
					}
					if(port != -1){
						portString = Integer.toString(port);
						if(dns.endsWith(":"+portString))
							dnsString = dns.replace(":"+portString, "");
						else 
							dnsString = dns;
						
						Indicator portIndicator = new Indicator()
							.withTypes(new ControlledVocabularyStringType()
								.withValue("Port"))
							.withObservable(new Observable()			//list
								.withObservableSources(new MeasureSourceType()
									.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
										.withValue("Sophos")))
								.withObject(new ObjectType()
									.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
										.withValue(portString)) 
									.withProperties(new Port()
										.withPortValue(new PositiveIntegerObjectPropertyType()
											.withValue(portString)))));
											
						indicators
							.withIndicators(portIndicator); 

					}else{ //shouldn't ever give -1 anyway
						logger.warn("could not find port for dns string {}", dns);
						portString = "unknown";
						dnsString = dns;
					}
					
					//Note that all other address nodes so far are named ip:port, but this is the best we can do here with the provided info.
					// Note that if any sophos entries have IPs and DNS names, then the IPs will be *in addition* to those DNS names, they will not correspond to those resolved names
					//TODO: if any counterexamples are found, revisit.
					String addressName = dnsString + ":" + portString;
					String addressDesc = dnsString + ", port " + portString;
					
					Indicator addressIndicator = new Indicator()
						.withTypes(new ControlledVocabularyStringType()
							.withValue("Address"))
						.withObservable(new Observable()
							.withObservableSources(new MeasureSourceType()
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("Sophos")))
							.withObject(new ObjectType()
								.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
									.withValue(addressDesc)) 
								.withProperties(new Address()
									.withAddressValue(new StringObjectPropertyType()
										.withValue(addressName))
									.withCategory(CategoryTypeEnum.IPV_4_ADDR))));
					indicators
						.withIndicators(addressIndicator); 
					
					Indicator dnsIndicator = new Indicator()
						.withTypes(new ControlledVocabularyStringType()
							.withValue("DNSName"))
						.withObservable(new Observable()
							.withObservableSources(new MeasureSourceType()
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("Sophos")))
							.withObject(new ObjectType()
								.withProperties(new DNSRecord()
									.withDomainName(new URIObjectType()
										.withValue(new AnyURIObjectPropertyType()
											.withValue(dnsString)))
									.withDescription(new org.mitre.cybox.common_2. StructuredTextType()
										.withValue(dnsString)))));
					indicators							
						.withIndicators(dnsIndicator); 
									
				}
			}
		}
		
			indicators
				.withIndicators(indicator 
					.withTypes(new ControlledVocabularyStringType()
						.withValue("Malware"))
					.withObservable(new Observable()	
						.withObservableComposition(observableComposition))
					.withIndicatedTTPs(new RelatedTTPType()
						.withTTP(ttp
							.withBehavior(new BehaviorType()
								.withMalware(new MalwareType()
									.withMalwareInstances(new MalwareInstanceType()
										.withNames(new ControlledVocabularyStringType()
											.withValue(vertexName))
										.withTypes(types)
										.withDescriptions(new StructuredTextType()
											.withValue(vertexName)))))
							.withInformationSource(new InformationSourceType()
								.withIdentity(new IdentityType()
									.withName("Sophos")))
							.withVictimTargeting(new VictimTargetingType()
								.withTargetedSystems(new ControlledVocabularyStringType()
									.withValue(platformName))))));
												
			stixPackage 											
				.withIndicators(indicators);
				
		//TODO put some remaining free text in desc? (Not always present...)
		//vertex.put("description", content.text());
		
	    	return stixPackage;
		
		} catch(DatatypeConfigurationException e)	{
			e.printStackTrace();
		} catch(NumberFormatException e)	{
			e.printStackTrace();
		}
		return null;
	}
	
	CustomPropertiesType customiseProperty (String name, Object value)	{
	
		CustomPropertiesType property = new CustomPropertiesType()
			.withProperties(new Property()
				.withName(name)
				.withValue(value));		
		return property;
	}		
							
	List<AssociatedObjectType> getFiles (Set<String> items)	{
														
		List<AssociatedObjectType> files = new ArrayList<AssociatedObjectType>();

		for (String item: items)	{
			files.add(new AssociatedObjectType()
				.withProperties(new FileObjectType()
					.withFileName(new StringObjectPropertyType()
						.withValue(item))));
		}
		
		return files;
	}
	
	HashType getHash (String type, String hash)	{
				
		HashType hashType = new HashType();
		
		hashType
			.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
				.withValue(type))
			.withSimpleHashValue(new SimpleHashValueType()
				.withValue(hash));		
		
		return hashType;
	}
	
	List<AssociatedObjectType> getProcesses (Set<String> items)	{
													
		List<AssociatedObjectType> processes = new ArrayList<AssociatedObjectType>();

		for (String item: items)	{

			processes.add(new AssociatedObjectType()
				.withProperties(new ProcessObjectType()
					.withName(new StringObjectPropertyType()
						.withValue(item))));
		}
		
		return processes;
	}

	
							
	List<AssociatedObjectType> getRegistryKeys (Set<String> items)	{
																				
		List<AssociatedObjectType> registryKeys = new ArrayList<AssociatedObjectType>();

		for (String item: items)	{
				
			registryKeys.add(new AssociatedObjectType()
				.withProperties(new WindowsRegistryKey()
					.withKey(new StringObjectPropertyType()
						.withValue(item))));
		}
		
		return registryKeys;
	}
																		
	MalwareActionType getActions (String actionType, String actionDescription, Set<AssociatedObjectType> actionSet)	{
																
		MalwareActionType actions = new MalwareActionType()				
				.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
					.withValue(actionType))
				.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
					.withValue(actionDescription))	
				.withAssociatedObjects(new AssociatedObjectsType()
					.withAssociatedObjects(actionSet));
			//	.withFrequency(new FrequencyType()
			//		.withScale(prevalence));
									
		return actions;
	}
							
	ToolsType getTools(String type, Set<String> newItems)	{
						
		ToolsType tools = new ToolsType();
		
		for (String item: newItems)	{
		tools
			.withTools(new ToolInformationType()
				.withName(item)					
				.withTypes(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
					.withValue(type)));
		}
	
		return tools;
	}

	boolean validate(STIXPackage stixPackage) {
		
		try     {
			return stixPackage.validate();
		}
		catch (SAXException e)	{
			e.printStackTrace();
		}
			return false;
	}
	
}

	/*	Indicator ind = new Indicator()
			.withAlternativeIDs("id")	// list: Collection<String>
			.withObservable(new Observable()	
				.withObservableComposition(new ObservableCompositionType()
					.withObservables(new Observable()			//list
						.withObject(new ObjectType()
							.withProperties(new FileObjectType()
								.withFileName(new StringObjectPropertyType()
									.withValue("name"))
								.withCustomProperties(new CustomPropertiesType()
									.withProperties(new Property()		//list
										.withName("customProperty")
										.withValue("value"))) 
								.withModifiedTime(new DateTimeObjectPropertyType()
									.withValue("time"))
								.withHashes(new HashListType()
									.withHashes(new HashType()	//list
										.withType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
											.withValue("type"))
										.withSimpleHashValue(new SimpleHashValueType()	
											.withValue("value")))))))));

	*/

