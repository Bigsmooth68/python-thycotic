# python-thycotic
Python Thycotic class for easier and faster password retrieval

# Usage
Constructor:
```python
myToken = Secrets('https://url/','User1','Password1',getKeyFunction)
Where getKeyFunction is a pointer to a function returning secret ID based on hostname.
```
Retrieve credentials:
```python
credentials = myToken.getCredentials(hostname)
```
Where hostname is the key.
