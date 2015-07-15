package HTMLExtractor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;

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
		graph = extract(summary, details);
	}
	
	public JSONObject getGraph() {
		return graph;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time, "dd MMM yyyy hh:mm:ss (z)");
	}
	
	private long convertShortTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "yyyy-MM-dd (z)");
	}
	
	private JSONObject extract(String summary, String details){
	
		JSONObject graph = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();
		JSONObject edge;
	
		JSONObject vertex = new JSONObject();

		try	{

		Indicator indicator = new Indicator();
		TTP ttp = new TTP();																
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

		System.out.println(discoveredDateTime.toXMLString(true));
		
		//process the "summary" page
		Document doc = Jsoup.parse(summary);
		Element content = doc.getElementsByClass("tertiaryBump").first();
		logger.debug(content.html());
		
		//get the title, set up name & other known fields
		Element titleDiv = content.getElementsByClass("marqTitle").first();
		logger.debug(titleDiv.html());
		String vertexName = titleDiv.getElementsByTag("h1").first().text();
		logger.info("Name: {}", vertexName);
	
		vertex.put("name", vertexName);						//name
		vertex.put("_id", vertexName);						//id
		vertex.put("_type", "vertex");							
		vertex.put("vertexType", "malware");					//vertexType = "malware"
		vertex.put("source", "Sophos");						//source	
		
		Element rowOne = titleDiv.getElementsByTag("tr").first();
		String addedDate = rowOne.child(3).text();
		if(!addedDate.equals("")){//some don't list dates, not sure why
			vertex.put("signatureDate", convertTimestamp(addedDate));	//signatureDate = date
			vertex.put("discoveryDate", convertTimestamp(addedDate));	//discoveryDate = date
			
			discoveredDateTime
				.setValue(Long.toString(convertTimestamp(addedDate)));	//has to be a string, or toXMLString() would not work
			signatureDate = convertTimestamp(addedDate);
		}			
		
		Element rowTwo = titleDiv.getElementsByTag("tr").get(1);
		String type = rowTwo.child(1).text();
		TreeSet<String> typeSet = new TreeSet<String>();
		typeSet.add(type);
		vertex.put("malwareType", typeSet);					//malwareType = typesSEt
																				
		List<ControlledVocabularyStringType> types = new ArrayList<ControlledVocabularyStringType>();
		types.add(new ControlledVocabularyStringType()
			.withValue(type));
																			
		String modifiedDate = rowTwo.child(3).text();
		if(!modifiedDate.equals(""))	{
			vertex.put("modifiedDate", convertTimestamp(modifiedDate));	//modifiedDate
			modifiedDateTime 
				.setValue(Long.toString(convertTimestamp(addedDate)));
		}

		Element rowThree = titleDiv.getElementsByTag("tr").get(2);
		String prev = rowThree.child(1).getElementsByTag("img").first().attr("alt");
		vertex.put("prevalence", prev); //TODO: convert labels into int levels, or similar?	//prevalence
		logger.info("Prevalence: {}", prev);
		prevalence 
			.withValue(prev);

		//handle secondary div
		Element secondaryDiv = doc.getElementsByClass("secondaryContent").first();
		logger.debug(secondaryDiv.html());
		Elements aliasItems = secondaryDiv.getElementsByClass("aliases");
		if(aliasItems != null && aliasItems.size() > 0){ //some don't have any listed.
			aliasItems = aliasItems.first().children();
			logger.debug(aliasItems.outerHtml());
			List<String> aliasList = new ArrayList<String>();
			for(int i=0; i<aliasItems.size(); i++){
				aliasList.add(aliasItems.get(i).text());
			}
			aliasList.add(vertexName);
			//TODO: how best to handle aliases in the long term?
			TreeSet<String> aliasSet = new TreeSet<String>();
			aliasSet.addAll(aliasList);//make into set, in case duplicates.
			vertex.put("aliases", aliasSet);							//alternativeID
			logger.info("Found {} items in aliasList:", aliasList.size());
			for(int i=0; i<aliasList.size(); i++){
				logger.info(aliasList.get(i));
			}
								
			indicator 
				.withAlternativeIDs(aliasList);
		}
		Elements h3s = secondaryDiv.getElementsByTag("h3");
		Element affectedHeading = null;
		for(int i=0; i<h3s.size(); i++){
			if(h3s.get(i).text().equals("Affected Operating Systems")){
				affectedHeading = h3s.get(i);
				break;
			}
		}
		String platformName = affectedHeading.nextElementSibling().getElementsByTag("img").first().attr("alt");
		vertex.put("platform", platformName);								//platform	
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
		TreeSet<String> sha1 = new TreeSet<String>();
		TreeSet<String> md5 = new TreeSet<String>();
		TreeSet<String> crc32 = new TreeSet<String>();
		TreeSet<String> filetype = new TreeSet<String>();
		long firstSeen;
		boolean runtimeAnalysisFound = false;
													

		ObservableCompositionType observableComposition = new ObservableCompositionType();
		Set<Observable> set = new HashSet<Observable>();

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
				//	String name;

					logger.info("Extracted map from file info table: {}", currTableContents);
					if(currTableContents.containsKey("Size")){
						size.add(currTableContents.get("Size"));
					}
					if(currTableContents.containsKey("SHA-1")){
						sha1.add(currTableContents.get("SHA-1"));
						hashes.add(getHash("SHA-1", currTableContents.get("SHA-1")));
					}
					if(currTableContents.containsKey("MD5")){
						md5.add(currTableContents.get("MD5"));
						hashes.add(getHash("MD5", currTableContents.get("MD5")));
					}					
					if(currTableContents.containsKey("CRC-32")){
						crc32.add(currTableContents.get("CRC-32"));
						hashes.add(getHash("CRC-32", currTableContents.get("CRC-32")));
					}						
					if(currTableContents.containsKey("File type")){
			
						filetype.add(currTableContents.get("File type"));
						
						file
							.withFileName(new StringObjectPropertyType()
								.withValue(currTableContents.get("File type")));
					}
					if(currTableContents.containsKey("First seen")){
			
						firstSeen = convertShortTimestamp(currTableContents.get("First seen"));
						//have to do all those comvertions, or toXMLString() would not work ....	
						if(firstSeen < Long.parseLong(discoveredDateTime.getValue().toString())){
							discoveredDateTime.setValue(Long.toString(firstSeen));
							vertex.put("discoveryDate", firstSeen);
						}
					}	
					if (!hashes.isEmpty())
						file
							.withHashes(new HashListType()
								.withHashes(hashes));
				//	observableComposition
				//		.withObservables(new Observable()
				//			.withObject(new ObjectType()
				//				.withProperties(file)));							
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
					JSONArray aliasArr = vertex.optJSONArray("aliases");
					Set<String> aliasSet = JSONArrayToSet(aliasArr);
					Set<String> keys = currTableContents.keySet();
					Iterator<String> keysIter = keys.iterator();
					while(keysIter.hasNext()){
						aliasSet.add(currTableContents.get(keysIter.next()));
					}
					logger.info("  now know aliases: {}", aliasSet);
					vertex.put("aliases", aliasSet);					//aliases
					
					indicator
						.withAlternativeIDs(aliasSet);
				}
			}else{
				logger.warn("Unexpected H4 Found: {}", curr.text());
			}
		}
		
		observableComposition
			.withObservables(set);
								
		//adding discoveredDate and modifiedDate
		observableComposition
			.withObservables(new Observable()			//list
				.withObject(new ObjectType()
					.withProperties(new Custom()
						.withCustomProperties(new CustomPropertiesType()
							.withProperties(discoveredDateTime)
							.withProperties(modifiedDateTime)
							.withProperties(prevalence)))));
											
		//use what you've learned.
		//if(size.size() > 0){} //not keeping this one
		if(sha1.size() > 0) vertex.put("sha1Hashes", sha1);					//sha1
		if(md5.size() > 0) vertex.put("md5Hashes", md5);					//md5
		//if(crc32.size() > 0){} //not keeping this one
		if(filetype.size() > 0) vertex.put("knownFileTypes", filetype);				//fileType
		
		//handle the "Runtime Analysis" sections...
		if(runtimeAnalysisFound){
			Element nextNextSibling;
			TreeSet<String> filesCreated = new TreeSet<String>();
			TreeSet<String> filesModified = new TreeSet<String>();
			TreeSet<String> registryKeysCreated = new TreeSet<String>();
			TreeSet<String> registryKeysModified = new TreeSet<String>();
			TreeSet<String> processesCreated = new TreeSet<String>();
			TreeSet<String> ipConnections = new TreeSet<String>();
			TreeSet<String> dnsRequests = new TreeSet<String>();
			TreeSet<String> urlsUsed = new TreeSet<String>();
													
			Set<AssociatedObjectType> createdFiles = new HashSet<AssociatedObjectType>();;
			Set<AssociatedObjectType> modifiedFiles = new HashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> createdProcesses = new HashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> createdRegistryKeys = new HashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> modifiedRegistryKeys = new HashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> ips = new HashSet<AssociatedObjectType>();
			Set<AssociatedObjectType> dnss = new HashSet<AssociatedObjectType>();
																				
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
							filesCreated.addAll(newItems);
							createdFiles.addAll(getFiles(newItems));
							logger.info("Dropped Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Copies Itself To")){
							//TODO save other fields?  MD5 & etc?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							filesCreated.addAll(newItems);
							createdFiles.addAll(getFiles(newItems));
							logger.info("Copies Itself To: {}", newItems);
						}
			 		else if(nextSibling.text().equals("Modified Files")){
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							filesModified.addAll(newItems);
							modifiedFiles.addAll(getFiles(newItems));
							logger.info("Modified Files: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Created")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							registryKeysCreated.addAll(newItems);
							createdRegistryKeys.addAll(getRegistryKeys(newItems));
							logger.info("Registry Keys Created: {}", newItems);
						}
						else if(nextSibling.text().equals("Registry Keys Modified")){
							//TODO save other fields?
							newItems = ulToSet(removeGrandchildren(nextNextSibling));
							registryKeysModified.addAll(newItems);
							modifiedRegistryKeys.addAll(getRegistryKeys(newItems));
							logger.info("Registry Keys Modified: {}", newItems);
						}
						else if(nextSibling.text().equals("Processes Created")){
							newItems = ulToSet(nextNextSibling);
							processesCreated.addAll(newItems);
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
							urlsUsed.addAll(newItems);
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

			AssociatedObjectsType objects = new AssociatedObjectsType();
			ActionsType actions = new ActionsType();
					
			if(filesCreated.size() > 0) vertex.put("filesCreated", filesCreated);
			if(filesModified.size() > 0) vertex.put("filesModified", filesModified);
			if(registryKeysCreated.size() > 0) vertex.put("registryKeysCreated", registryKeysCreated);
			if(registryKeysModified.size() > 0) vertex.put("registryKeysModified", registryKeysModified);
			if(processesCreated.size() > 0) vertex.put("processesCreated", processesCreated);
			if(urlsUsed.size() > 0) vertex.put("urlsUsed", urlsUsed);
														
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
			
		//	if(!foundFiles.isEmpty())	
		//		observable
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
					JSONObject portVertex = null;
					JSONObject ipVertex = null;
					JSONObject addressVertex = null;
					
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
						
						portVertex = new JSONObject();
						portVertex.put("name", portString);
						portVertex.put("description", portString);
						portVertex.put("_id", portString);
						portVertex.put("_type", "vertex");
						portVertex.put("vertexType", "port");
						portVertex.put("source", "Sophos");
						vertices.put(portVertex);
		
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
					
					addressVertex = new JSONObject();
					String addressName = ipString + ":" + portString;
					String addressDesc = ipString + ", port " + portString;
					addressVertex.put("name", addressName);
					addressVertex.put("description", addressDesc);
					addressVertex.put("_id", addressName);
					addressVertex.put("_type", "vertex");
					addressVertex.put("vertexType", "Address");
					addressVertex.put("source", "Sophos");
					vertices.put(addressVertex);
					
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

					edge = new JSONObject();
					edge.put("_inV", addressName);
					edge.put("_outV", vertex.get("name"));
					edge.put("_id", vertex.get("name") + "_communicatesWith_" + addressName);
					edge.put("description", vertex.get("name") + " communicates with " + addressDesc);
					edge.put("_type", "edge");
					edge.put("inVType", "address");
					edge.put("outVType", "malware");
					edge.put("source", "Sophos");
					edge.put("_label", "communicatesWith");
					edges.put(edge);
					
					if(portVertex != null){
						edge = new JSONObject();
						edge.put("_inV", portString);
						edge.put("_outV", addressName);
						edge.put("_id", addressName + "_hasPort_" + portString);
						edge.put("description", addressDesc + " has port " + portString);
						edge.put("_type", "edge");
						edge.put("inVType", "port");
						edge.put("outVType", "address");
						edge.put("source", "Sophos");
						edge.put("_label", "hasPort");
						edges.put(edge);
					}
					
					ipVertex = new JSONObject();
					ipVertex.put("name", ipString);
					ipVertex.put("description", ipString);
					ipVertex.put("_id", ipString);
					ipVertex.put("_type", "vertex");
					ipVertex.put("vertexType", "ip");
					ipVertex.put("source", "Sophos");
					vertices.put(ipVertex);
					
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
					
					edge = new JSONObject();
					edge.put("_inV", ipString);
					edge.put("_outV", addressName);
					edge.put("_id", addressName + "_hasIP_" + ipString);
					edge.put("description", addressDesc + " has IP " + ipString);
					edge.put("_type", "edge");
					edge.put("inVType", "ip");
					edge.put("outVType", "address");
					edge.put("source", "Sophos");
					edge.put("_label", "hasIP");
					edges.put(edge);
				}
			}
			
			//if() vertex.put("dnsRequests", dnsRequests); //TODO: make vertex
			//now handle the DNS info the same way
			if(dnsRequests.size() > 0){
				for(String dns : dnsRequests){
					String dnsString, portString;
					JSONObject portVertex = null;
					JSONObject dnsVertex = null;
					JSONObject addressVertex = null;
					
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
						
						portVertex = new JSONObject();
						portVertex.put("name", portString);
						portVertex.put("description", portString);
						portVertex.put("_id", portString);
						portVertex.put("_type", "vertex");
						portVertex.put("vertexType", "port");
						portVertex.put("source", "Sophos");
						vertices.put(portVertex);
						
						//there is no stix field for port description .... but it is the same as name (value)
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
					addressVertex = new JSONObject();
					String addressName = dnsString + ":" + portString;
					String addressDesc = dnsString + ", port " + portString;
					addressVertex.put("name", addressName);
					addressVertex.put("description", addressDesc);
					addressVertex.put("_id", addressName);
					addressVertex.put("_type", "vertex");
					addressVertex.put("vertexType", "Address");
					addressVertex.put("source", "Sophos");
					vertices.put(addressVertex);
					
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
					
					edge = new JSONObject();
					edge.put("_inV", addressName);
					edge.put("_outV", vertex.get("name"));
					edge.put("_id", vertex.get("name") + "_communicatesWith_" + addressName);
					edge.put("description", vertex.get("name") + " communicates with " + addressDesc);
					edge.put("_type", "edge");
					edge.put("inVType", "address");
					edge.put("outVType", "malware");
					edge.put("source", "Sophos");
					edge.put("_label", "communicatesWith");
					edges.put(edge);
					
					if(portVertex != null){
						edge = new JSONObject();
						edge.put("_inV", portString);
						edge.put("_outV", addressName);
						edge.put("_id", addressName + "_hasPort_" + portString);
						edge.put("description", addressDesc + " has port " + portString);
						edge.put("_type", "edge");
						edge.put("inVType", "port");
						edge.put("outVType", "address");
						edge.put("source", "Sophos");
						edge.put("_label", "hasPort");
						edges.put(edge);
					}
					
					dnsVertex = new JSONObject();
					dnsVertex.put("name", dnsString);
					dnsVertex.put("description", dnsString);
					dnsVertex.put("_id", dnsString);
					dnsVertex.put("_type", "vertex");
					dnsVertex.put("vertexType", "DNSName");
					dnsVertex.put("source", "Sophos");
					vertices.put(dnsVertex);
					
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
									
					edge = new JSONObject();
					edge.put("_inV", dnsString);
					edge.put("_outV", addressName);
					edge.put("_id", addressName + "_hasDNSName_" + dnsString);
					edge.put("description", addressDesc + " has DNS name " + dnsString);
					edge.put("_type", "edge");
					edge.put("inVType", "DNSName");
					edge.put("outVType", "address");
					edge.put("source", "Sophos");
					edge.put("_label", "hasDNSName");
					edges.put(edge);
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
				
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println(stixPackage.toXMLString(true));	
			System.out.println();
			System.out.println();
					//	.withObject(new ObjectType()

		//TODO put some remaining free text in desc? (Not always present...)
		//vertex.put("description", content.text());
		vertex.put("description", vertexName);
	    
		vertices.put(vertex);
		
		graph.put("mode","NORMAL");
		graph.put("vertices", vertices);
		graph.put("edges", edges);
		
	    	return graph;
		
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
}
