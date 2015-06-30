/*
	Outputs Bugtraq in STIX format containing the following fields:
		- CVE
		- publishedDate
		- Vulnerable
		- description
		- solution
		- references
		- shortDescription
		- source (is a title at the STIXHeader)
*/

package HTMLExtractor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;

import java.text.*;

import org.json.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.extensions.vulnerability.CVRF11InstanceType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.cybox.common_2.TimeType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;			

public class BugtraqToStixExtractor extends HTMLExtractor{
							
	private STIXPackage stixPackage;
	private static final Logger logger = LoggerFactory.getLogger(BugtraqExtractor.class);

	//empty constractor for test purpose
	public BugtraqToStixExtractor(){};

	public BugtraqToStixExtractor(String info, String discussion, String exploit, 
			String solution, String references){
		stixPackage = extract(info, discussion, exploit, solution, references);
	}
	
	public STIXPackage getGraph() {
		return stixPackage;
	}
	
	private long convertTimestamp(String time)	{ 
		return convertTimestamp(time + " (GMT)", "MMM dd yyyy hh:mma (z)");
	}
				
	private STIXPackage extract(String info, String discussion, String exploit, 
			String solution, String references){
		
		//TODO  missing fields: 
		//			vertexType - it is already know as a vulnerability in stix
		//			_type 
		//			modifiedDate - maybe value of a timestamp attribute?
		//			accessVector
		// 			credit
		// 			notVulnerable	
		// 			exploit
		//			class	
		try {

			GregorianCalendar calendar = new GregorianCalendar();
 			List<ExploitTargetBaseType> et = new ArrayList<ExploitTargetBaseType>();		
			ExploitTarget exploitTarget = new ExploitTarget();
			VulnerabilityType vulnerability = new VulnerabilityType();
					
			//process the "info" page
			Document doc = Jsoup.parse(info);
			Element content = doc.getElementById("vulnerability");
		
			logger.debug(content.html());
			logger.debug(content.getElementsByClass("title").first().text());
			
			//shortDescription
 			vulnerability
				.withShortDescriptions(new StructuredTextType()
					.withValue(content.getElementsByClass("title").first().text()));

			//TODO what to do with this id?
			String regex = "(?s)\\s*?<td>.*?<span.*?>Bugtraq ID:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
			String bugtraqID = findWithRegex(content.html(), regex, 1);
			
			//source
			vulnerability
				.withSource("Bugtraq");
			
	    		regex = "(?s)\\s*?<td>.*?<span.*?>CVE:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String cve = findWithRegex(content.html(), regex, 1).replaceAll("<br\\s*/>", "");
			
			//CVE
			if (!isEmpty(cve))
				vulnerability
					.withCVEID(cve);
			
	    		regex = "(?s)\\s*?<td>.*?<span.*?>Published:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String publishedTS = findWithRegex(content.html(), regex, 1);
			calendar.setTimeInMillis(convertTimestamp(publishedTS));
			XMLGregorianCalendar publishedDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
			
			//publishedDate
			vulnerability
				.withDiscoveredDateTime(new DateTimeWithPrecisionType()
					.withValue(publishedDate));	    

	    		regex = "(?s)\\s*?<td>.*?<span.*?>Vulnerable:</span>.*?</td>.*?<td>\\s*(.*?)\\s*</td>";
	    		String[] vulnerable = findWithRegex(content.html(), regex, 1).split("<br\\s*/>");
	    		trimAll(vulnerable);
	    		ArrayList<String> vulnerableList = new ArrayList<String>(Arrays.asList(vulnerable));
			//remove the plus and minus sub-entries.
			//see eg. http://www.securityfocus.com/bid/149/info
			String item;
			for(int i=vulnerableList.size()-1; i>=0; i--){
				item = vulnerableList.get(i);
				if(item.equals("")){
					vulnerableList.remove(i);
				}else if(item.contains("<span class=\"related\">")){
					vulnerableList.remove(i);
				}else if(item.equals("</span>")){
					vulnerableList.remove(i);
				}else if(item.contains("</span>")){
					vulnerableList.set(i, item.replaceAll("</span>\\s*", ""));
				}
			}
			
			//Vulnerable
			List<RelatedObservableType> relatedObservable = new ArrayList<RelatedObservableType>();
 			if (!vulnerableList.isEmpty())	{
				for (int j = 0; j < vulnerableList.size(); j++)       {
					relatedObservable.add(new RelatedObservableType()
						.withObservable(new Observable()
							.withObject(new ObjectType()
								.withProperties(new Product()
									.withProduct(new StringObjectPropertyType()
										.withValue(vulnerableList.get(j)))
 					))));
				}
				vulnerability
					.withAffectedSoftware(new AffectedSoftwareType()
						.withAffectedSoftwares(relatedObservable));
			}	    

			//process the "discussion" page
			doc = Jsoup.parse(discussion);
			content = doc.getElementById("vulnerability");
			
			//description
			if (!isEmpty(content.text()))	{
				vulnerability
					.withDescriptions(new StructuredTextType()
						.withValue(content.text()));
			}								

			//TODO add action to the stix schema
			//process the "solution" page
			doc = Jsoup.parse(solution);
			content = doc.getElementById("vulnerability");
			doc.getElementsByClass("title").first().remove();
			 
			//solution 
	  		if (!isEmpty(content.text()))	{
				PotentialCOAsType coa = new PotentialCOAsType();
				coa							
					.withPotentialCOAs(new RelatedCourseOfActionType()
						.withCourseOfAction(new CourseOfAction()
							.withDescriptions(new StructuredTextType()
								.withValue(content.text())
				)));						
				exploitTarget
					.withPotentialCOAs(coa);				
			}						
				
			//process the "references" page
			doc = Jsoup.parse(references);
			content = doc.getElementById("vulnerability");
			doc.getElementsByClass("title").first().remove();
			ArrayList<String> refStrings = findAllLinkHrefs(content);
			
			//references
			if(!refStrings.isEmpty())	{
				vulnerability
					.withReferences(new ReferencesType()
						.withReferences(refStrings));
			}

			et.add(exploitTarget
				.withVulnerabilities(vulnerability)
				.withId(new QName("stucco", "bugtraq-" + UUID.randomUUID().toString(), "stucco")));
 															
			XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC")));
			InformationSourceType producer = new InformationSourceType()
	                     	.withTime(new TimeType()
 					.withProducedTime(new org.mitre.cybox.common_2.DateTimeWithPrecisionType(now, null)));
			STIXHeaderType header = new STIXHeaderType().withTitle("Bugtraq");
			stixPackage = new STIXPackage()
 				.withSTIXHeader(header)
				.withExploitTargets(new ExploitTargetsType()
					.withExploitTargets(et))
				.withTimestamp(now)
 				.withId(new QName("stucco", "bugtraq-" + UUID.randomUUID().toString(), "stucco"));
				
		    	return stixPackage;
		
		} catch (DatatypeConfigurationException e)      {
			 e.printStackTrace();
		}
		
		return null;
	}
																					
	boolean validate(STIXPackage stixPackage) {
		try	{
			return stixPackage.validate();
		}			
		catch (SAXException e)	{
			e.printStackTrace();
		}
		return false;
	}
}
