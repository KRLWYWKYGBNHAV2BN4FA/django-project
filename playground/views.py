from bs4 import BeautifulSoup
from django.shortcuts import render
from django.http import HttpResponse
import requests
from django.views.generic import TemplateView
from django.shortcuts import render
from io import BytesIO
from django.template.loader import get_template
from django.views import View
from xhtml2pdf import pisa
import pdfkit
import json



API_KEY = "a00812e9-f9b1-4ea0-b1e2-28d220f382b5"


def home_view(request):
    return render(request, "homepage.html")

def get_new_pdf(request):
    template_path = "/home/mark/Desktop/Cybervibe/Python/jangofront/playground/templates/get_new_pdf.html"
    context = {"cves": get_new_cve(request)}
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=new.pdf"
    template = get_template(template_path)
    html = template.render(context)
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse("404")
    return response

def get_all_pdf(request):
    template_path = "/home/mark/Desktop/Cybervibe/Python/jangofront/playground/templates/get_all_pdf.html"
    context = {"cves2": get_all_cve(request)}
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=all.pdf"
    template = get_template(template_path)
    html = template.render(context)
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse("404")
    return response

def get_crit_pdf(request):
    template_path = "/home/mark/Desktop/Cybervibe/Python/jangofront/playground/templates/get_crit_pdf.html"
    context = {"cves3": get_crit_cve(request)}
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=crit.pdf"
    template = get_template(template_path)
    html = template.render(context)
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse("404")
    return response

def get_crit_cve(request):
    url = requests.get("https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cvss_version=3&cvss_v3_severity=CRITICAL")
    vuln_id = []
    summary = []
    date = []
    cvss = []
    html = BeautifulSoup(url.text, "html.parser")
    mtable = html.find("table", {"class": "table"})
    tbody = mtable.find("tbody")
    for tr in tbody.find_all("tr"):
        for th in tr.find_all("th"):
            for a in th.find("a"):
                vuln_id.append(a)
            for p in tr.find("p"):
                summary.append(p)
            for span in tr.find("span"):
                date.append(span)
        for td in tr.find_all("td"):
            for span in td.find_all("span"):
                for em in span.find_all("a", class_="label"):
                    cvss.append(em.text)

    context = []
    for i in range(20):
        context.append(vuln_id[i])
        context.append(date[i])
        context.append(cvss[i])
        context.append(summary[i])

    return render(request, "get_new.html", {"context": context})


def get_new_cve(request):
    url = requests.get("https://nvd.nist.gov/vuln/search/results?results_type=overview&search_type=all&form_type=Advanced&isCpeNameSearch=false&cvss_version=3&orderBy=modifiedDate&orderDir=desc")
    vuln_id = []
    summary = []
    date = []
    cvss = []
    html = BeautifulSoup(url.text, "html.parser")
    mtable = html.find("table", {"class": "table"})
    tbody = mtable.find("tbody")
    for tr in tbody.find_all("tr"):
        for th in tr.find_all("th"):
            for a in th.find("a"):
                vuln_id.append(a)
            for p in tr.find("p"):
                summary.append(p)
            for span in tr.find("span"):
                date.append(span)
        for td in tr.find_all("td"):
            for span in td.find_all("span"):
                for em in span.find_all("a", class_="label"):
                    cvss.append(em.text)

    context = []
    for i in range(20):
        context.append(vuln_id[i])
        context.append(date[i])
        context.append(cvss[i])
        context.append(summary[i])

    return render(request, "get_new.html", {"context": context})


def get_all_cve(request):
    url = requests.get("https://nvd.nist.gov/vuln/search/results?results_type=overview&search_type=all&form_type=Advanced&isCpeNameSearch=false&cvss_version=3&orderBy=publishDate&orderDir=desc")
    vuln_id = []
    summary = []
    date = []
    cvss = []
    html = BeautifulSoup(url.text, "html.parser")
    mtable = html.find("table", {"class": "table"})
    tbody = mtable.find("tbody")
    for tr in tbody.find_all("tr"):
        for th in tr.find_all("th"):
            for a in th.find("a"):
                vuln_id.append(a)
            for p in tr.find("p"):
                summary.append(p)
            for span in tr.find("span"):
                date.append(span)
        for td in tr.find_all("td"):
            for span in td.find_all("span"):
                for em in span.find_all("a", class_="label"):
                    cvss.append(em.text)

    context = []
    for i in range(20):
        context.append(vuln_id[i])
        context.append(date[i])
        context.append(cvss[i])
        context.append(summary[i])

    return render(request, "get_all.html", {"context": context})
