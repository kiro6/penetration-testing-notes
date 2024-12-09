
## `WSDL:Web Services Description Language` is an XML-based language that is used to describe the functionality offered by a web service

## WDSL can be used for SOAP or REST APIs but is more associated with XML Based APIs

## This Videos explain `WDSL` very well
- [explain WDSL in Arabic](https://youtu.be/Xm9cN1dQ3Cg)
- [explain WDSL in English](https://youtu.be/E76xW1JTVXY)


## I will use this example to explain `WDSL` 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions targetNamespace="http://tempuri.org/"
	xmlns:s="http://www.w3.org/2001/XMLSchema"
	xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
	xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
	xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/"
	xmlns:tns="http://tempuri.org/"
	xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"
	xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
	xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">



<wsdl:types>
		<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
			<s:element name="LoginRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
						<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="LoginResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
		</s:schema>


</wsdl:types>




	<!-- Login Messages -->
	<wsdl:message name="LoginSoapIn">
		<wsdl:part name="parameters" element="tns:LoginRequest"/>
	</wsdl:message>
	<wsdl:message name="LoginSoapOut">
		<wsdl:part name="parameters" element="tns:LoginResponse"/>
	</wsdl:message>
	<!-- ExecuteCommand Messages -->
	<wsdl:message name="ExecuteCommandSoapIn">
		<wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
	</wsdl:message>
	<wsdl:message name="ExecuteCommandSoapOut">
		<wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
	</wsdl:message>




	<wsdl:portType name="HacktheBoxSoapPort">
		<!-- Login Operaion | PORT -->
		<wsdl:operation name="Login">
			<wsdl:input message="tns:LoginSoapIn"/>
			<wsdl:output message="tns:LoginSoapOut"/>
		</wsdl:operation>
		<!-- ExecuteCommand Operation | PORT -->
		<wsdl:operation name="ExecuteCommand">
			<wsdl:input message="tns:ExecuteCommandSoapIn"/>
			<wsdl:output message="tns:ExecuteCommandSoapOut"/>
		</wsdl:operation>
	</wsdl:portType>



	<wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
		<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
		<!-- SOAP Login Action -->
		<wsdl:operation name="Login">
			<soap:operation soapAction="Login" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
		<!-- SOAP ExecuteCommand Action -->
		<wsdl:operation name="ExecuteCommand">
			<soap:operation soapAction="ExecuteCommand" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
	</wsdl:binding>


	<wsdl:service name="HacktheboxService">
		<wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
			<soap:address location="http://localhost:80/wsdl"/>
		</wsdl:port>
	</wsdl:service>
</wsdl:definitions>
```


##  WSDL  components:

- **Name**: The name attribute provides a unique identifier for the service within the WSDL document.

- **Port**: A port is a specific endpoint within the service. It defines the network address where the service is accessible and the communication protocol to be used, such as SOAP over HTTP or SOAP over SMTP.

- **Binding**: A binding is an association between a specific port and the protocol and data format used for communication. It links the abstract interface of the service to a concrete network protocol.

-  **Operation**: An operation represents an individual functionality or action that the web service offers. Each operation is associated with input and output messages, defining the data that needs to be sent and received.

- **Message**: A message is an abstract definition of the data being exchanged between the client and the server during an operation. It defines the structure of the input and output data using XML.

- **Types**: The types section defines the data types used in the messages, such as complex data structures, simple data types, and enumerations.


## The best way in my opinion to read WDSL is from bottom to top
- always check relation between attribute names and other elements
- if you feel overwhelmed continue everything will get clear at the end


### service element : 
here we define our service endpoint and protocol 
```xml
<wsdl:service name="HacktheboxService">

<wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
<soap:address location="http://localhost:80/wsdl"/>
</wsdl:port>

</wsdl:service>
```

### binding element :
#### SOAP binding
- the `<wsdl:binding>` element is used to define the protocol and data format details for a specific port type, which represents an endpoint of the web service.
- For SOAP bindings, the `<wsdl:binding>` element contains: child elements like `<soap:binding>` and `<wsdl:operation>` elements that define how SOAP messages should be transmitted over a specific transport protocol (e.g., HTTP) and the style (e.g., document or RPC) for each operation. 
- It associates an abstract interface (defined in the `<wsdl:portType>` element) with a concrete network protocol, specifying how the messages should be formatted and transmitted over the network.

#### `<wsdl:binding>` contains the following attributes:

- **name**: A unique name that identifies the binding within the WSDL document.
- **type**: A QName (Qualified Name) that references the abstract interface (port type) defined in the `<wsdl:portType>` element, to which this binding corresponds.
```xml
<wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
		<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
		<!-- SOAP Login Action -->
		<wsdl:operation name="Login">
			<soap:operation soapAction="Login" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
		<!-- SOAP ExecuteCommand Action -->
		<wsdl:operation name="ExecuteCommand">
			<soap:operation soapAction="ExecuteCommand" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
	</wsdl:binding>
```



#### HTTP binding
- For HTTP bindings, the `<wsdl:binding>` element includes `<http:binding>` elements to define the details for the HTTP request and response messages. HTTP bindings are commonly used for RESTful web services.
```xml
<wsdl:binding name="HacktheboxServiceHTTPBinding" type="tns:HacktheboxServicePortType">
  <http:binding verb="POST"/>
  <wsdl:operation name="SomeOperation">
    <http:operation location="SomeOperation"/>
    <wsdl:input>
      <mime:content type="application/json"/>
    </wsdl:input>
    <wsdl:output>
      <mime:content type="application/json"/>
    </wsdl:output>
  </wsdl:operation>
  <!-- More operations go here -->
</wsdl:binding>

```





### portType element 
- here we define the operations for our service in abstract way 
- `operation name="Login"` this what is used in `SOAPAction` header
```xml
	<wsdl:portType name="HacktheBoxSoapPort">
		<!-- Login Operaion | PORT -->
		<wsdl:operation name="Login">
			<wsdl:input message="tns:LoginSoapIn"/>
			<wsdl:output message="tns:LoginSoapOut"/>
		</wsdl:operation>
		<!-- ExecuteCommand Operation | PORT -->
		<wsdl:operation name="ExecuteCommand">
			<wsdl:input message="tns:ExecuteCommandSoapIn"/>
			<wsdl:output message="tns:ExecuteCommandSoapOut"/>
		</wsdl:operation>
	</wsdl:portType>
```




### message element
- `<wsdl:message>` element is used to define the abstract message format for each operation in a web service. 
- These messages specify the structure of the data that will be exchanged between the client and the server during the execution of an operation.
```xml
<!-- Login Messages -->
	<wsdl:message name="LoginSoapIn">
		<wsdl:part name="parameters" element="tns:LoginRequest"/>
	</wsdl:message>
	<wsdl:message name="LoginSoapOut">
		<wsdl:part name="parameters" element="tns:LoginResponse"/>
	</wsdl:message>
	<!-- ExecuteCommand Messages -->
	<wsdl:message name="ExecuteCommandSoapIn">
		<wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
	</wsdl:message>
	<wsdl:message name="ExecuteCommandSoapOut">
		<wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
	</wsdl:message>
```





### types element 
define actual parameters in request or response and thier types
```xml
<wsdl:types>
		<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
			<s:element name="LoginRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
						<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="LoginResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
		</s:schema>


</wsdl:types>
```






## Example of soap request for this service 
```soap
<?xml version="1.0" encoding="utf-8"?>

<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:tns="http://tempuri.org/"
    xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
    <soap:Body>
        <ExecuteCommandRequest xmlns="http://tempuri.org/">
            <cmd>whoami</cmd>
        </ExecuteCommandRequest>
    </soap:Body>
</soap:Envelope> 
```
