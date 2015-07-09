package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Tag;
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
				
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;
import javax.xml.datatype.DatatypeConfigurationException;

import org.xml.sax.SAXException;

public class FSecureToStixExtractor extends HTMLExtractor{
	
	private STIXPackage stixPackage;
	private static final Logger logger = LoggerFactory.getLogger(FSecureToStixExtractor.class);
										
	public FSecureToStixExtractor(String pageContent){
		stixPackage = extractStixPackage(pageContent);
	}
	
	public STIXPackage getStixPackage() {
		return stixPackage;
	}
	
	//TODO: get timestamp from RSS?
	//private long convertTimestamp(String time)	{ 
	//}
	
	//This makes <p><b> text into <h4> text.
	//They are equivalent, but not used consistently between pages.
	private static void fixSectionHeaders(Elements contents){
		Element curr, replacement;
		Elements currChildren;
		for(int i = contents.size()-1; i>=0; i--){
			curr = contents.get(i);
			if(curr.tagName().equals("p")){
				currChildren = curr.children();
				if(currChildren.size() == 1 && currChildren.get(0).tagName().equalsIgnoreCase("b")){
					replacement = new Element(Tag.valueOf("h4"), "");
					replacement.text(curr.text());
					contents.remove(i);
					contents.add(i, replacement);
				}
			}
		}
	}
						
	private STIXPackage extractStixPackage(String pageContent){
				
		try {

		Document doc = Jsoup.parse(pageContent);
		
		MalwareInstanceType malware = new MalwareInstanceType();
		Indicator indicator = new Indicator();
		VictimTargetingType victim = new VictimTargetingType();		
		Observable observable = new Observable();
		InformationSourceType source = new InformationSourceType();
//		AttackPatternType technicalDetails = new AttackPatternType();
//		AttackPatternType distribution = new AttackPatternType();
													
		ArrayList attackPattern = new ArrayList();

		////////////////////////////////////
		//get the title, set up name & other known fields
		String vertexName = doc.getElementsByTag("title").first().text().replaceAll("\u200b", "").replaceAll("\\:\\?",":");
		
		logger.info("Name: {}", vertexName);
		
		//name as Indicator->TTP->Behavior->Malware->name			
		malware
			.withNames(new ControlledVocabularyStringType()
				.withValue(vertexName));
											
		//source as Indicator->TTP->InformationSourceType->source
		source
			.withContributingSources(new ContributingSourcesType()
				.withSources(new InformationSourceType()
					.withIdentity(new IdentityType()
						 .withName("F-Secure")
		)));								

		/////////////////////////////
		//parse the box at the top
		Element detailsTable = doc.getElementsByClass("details-table").first();
		String[][] cells = getCells(detailsTable.getElementsByTag("tr"));
		
		logger.debug("table contains: {}", new JSONArray(cells));
		
		String aliases = cells[0][1];
		String category = cells[1][1];
		String type = cells[2][1];
		String platform = cells[3][1];
		
		String[] aliasList = aliases.split(", ");
		logger.debug("Found {} items in aliasList:", aliasList.length);
		for(int i=0; i<aliasList.length; i++){
			logger.debug(aliasList[i]);
		}
		Set<String> aliasSet = new TreeSet<String>();
		for(String alias : aliasList){
			aliasSet.add(alias.replaceAll("\u200b", "").replaceAll("\\:\\?",":"));
		}
		aliasSet.add(vertexName);
		JSONArray aliasesResult = new JSONArray(aliasSet);
		logger.info("final alias list is: {}", aliasesResult);
		//TODO: how best to handle aliases in the long term?
		
		//aliases as Indicator->Alternative_ID
		indicator
			.withAlternativeIDs(aliasSet);			
							
		//keeping both fields as "malwareType", because they aren't used consistently

		ArrayList types = new ArrayList();
		
		types.add(new ControlledVocabularyStringType()
			.withValue(category));
		types.add(new ControlledVocabularyStringType()
			.withValue(type));
		
		//malwareType as Indicator->TTP->Behavior->Malware->Type
		malware
			.withTypes(types);

		//platform as Indicator->TTP->VictimTargeting->TargetedSystem			
		victim
			.withTargetedSystems(new ControlledVocabularyStringType()
				.withValue(platform));
										
		/////////////////////////
		//parse remaining page contents
		Element contentDiv = doc.select("div#maincontent").first().select("div.row").first().select("div").first();
		logger.debug(contentDiv.html());
		Elements contents = contentDiv.children().first().children();
		Element curr, prev;
		removeBRs(contents);
		removeHRs(contents);
		fixSectionHeaders(contents);
		logger.debug(contents.outerHtml());
		//System.out.println("contents size is now: " + contents.size());
		for(int i = contents.size()-1; i>0; i--){
			curr = contents.get(i);
			prev = contents.get(i-1);
			if(curr.tagName().equals("p") && prev.tagName().equals("p")){
				prev.text( prev.text() + "\n" + curr.text() );
				contents.remove(i);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("ul")){
				curr.text( ulToString(prev) + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("img")){
				//TODO
				curr.text( prev.attr("src") + "\n" + curr.text() );
				contents.remove(i-1);
				continue;
			}
			//pull out expected fields, based on headers...
			if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Technical Details")){
				//STIX short_description = details
				//TODO maybe move to the Observable?
				
				//details as Indicator->TTP->Behavior->Attack_Pattern->title & description
				attackPattern.add(new AttackPatternType()
					.withTitle("Details")
					.withDescriptions(new StructuredTextType()
						.withValue(curr.text())));

				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h2") && prev.text().equals("Summary")){
				//description as Indicator->TTP->Behavior->Malware->description
				malware
					.withDescriptions(new StructuredTextType()
						.withValue(curr.text()));

				contents.remove(i);
				contents.remove(i-1);
				i--;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h5") && prev.text().equals("Automatic action")){
				String removalMessage = curr.text();
				if(removalMessage.startsWith("Once detected, the F-Secure security product will automatically disinfect the suspect file")){
					//removal as Indicator->COA->description
					indicator
						.withSuggestedCOAs(new SuggestedCOAsType()
							.withSuggestedCOAs(new RelatedCourseOfActionType()
								.withCourseOfAction(new CourseOfAction()
									.withDescriptions(new StructuredTextType()
										.withValue("F-Secure")
					))));
				}else{
					//removal as Indicator->COA->description
					indicator
						.withSuggestedCOAs(new SuggestedCOAsType()
							.withSuggestedCOAs(new RelatedCourseOfActionType()
								.withCourseOfAction(new CourseOfAction()
									.withDescriptions(new StructuredTextType()
										.withValue("F-Secure: " + removalMessage)
					))));
				}
				contents.remove(i);
				contents.remove(i-1);
				contents.remove(i-2);
				i -= 2;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Distribution")){
				//distribution as Indicator->TTP->Behavior->Attack_Patterns->Title & description
				attackPattern.add(new AttackPatternType()
					.withTitle("Distribution")
					.withDescriptions(new StructuredTextType()
						.withValue(curr.text())));
				
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
			if(curr.tagName().equals("p") && prev.tagName().equals("h4") && prev.text().equals("Behavior")){
				//behavior as Indicator->Observable->description
				observable									
					.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
						.withValue(curr.text()));
													
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
			if(curr.tagName().equals("p") && (prev.tagName().equals("h5") || prev.tagName().equals("h4")) && prev.text().equals("More")){
				//Don't put contents anywhere for these, just ignore.
				contents.remove(i);
				contents.remove(i-1);
				i -= 1;
				continue;
			}
		}
		
		//having remaining text is somewhat common with these entries...
		logger.info("=====REMAINING:=====");
		logger.info(contents.outerHtml());
		logger.info("=========");
		
		XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
			new GregorianCalendar(TimeZone.getTimeZone("UTC")));
		InformationSourceType producer = new InformationSourceType()
	        	.withTime(new TimeType()
 				.withProducedTime(new org.mitre.cybox.common_2.DateTimeWithPrecisionType(now, null)));
		STIXHeaderType header = new STIXHeaderType().withTitle("F-Secure");
		indicator
			.withTypes(new ControlledVocabularyStringType()
				.withValue("Malware"))
			.withIndicatedTTPs(new RelatedTTPType()
				.withTTP(new TTP()
					.withBehavior(new BehaviorType()
						.withMalware(new MalwareType()
							.withMalwareInstances(malware))
						.withAttackPatterns(new AttackPatternsType()
							.withAttackPatterns(attackPattern)))
					.withVictimTargeting(victim)
					.withInformationSource(source)
			))
			.withObservable(observable);
		stixPackage = new STIXPackage()				
 			.withSTIXHeader(header)
			.withIndicators(new IndicatorsType().withIndicators(indicator))
			.withTimestamp(now)
 			.withId(new QName("stucco", "F-Secure-" + UUID.randomUUID().toString(), "stucco"));

		return stixPackage;
		
		} catch (DatatypeConfigurationException e)      {
			 e.printStackTrace();
		}	
	
		return null;
	}

	boolean validate(STIXPackage stixPackage) {
		try     {
			return stixPackage.validate();
		}
		catch (SAXException e)  {
			e.printStackTrace();
		}
		return false;
	}


	private static String ulToString(Element ul){
		String ret;
		ret = ul.text();
		logger.debug(":::ulToString is returning::: {}", ret);
		return ret;
	}
}
