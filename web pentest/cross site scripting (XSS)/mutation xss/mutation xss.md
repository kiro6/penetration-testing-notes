
### DOMPurify

is a JavaScript library that provides a secure way to sanitize and clean HTML code to prevent cross-site scripting (XSS) attacks.

### How Does DOMPurify Work?

-DOMPurify sanitizes user input by using the template element.

-Browsers process the innerHtml property of the div element and the same property of the template element differently.

-In the case of the div element, innerHtml is executed immediately after it is assigned a value. In the case of the template element, you can apply sanitization before execution.

-The idea behind DOMPurify is to take the user input, assign it to the innerHtml property of the template element, have the browser interpret it (but not execute it), and then sanitize it for potential XSS.

-However, it is the logic behind that interpretation that is the underlying cause of the mutation XSS.



