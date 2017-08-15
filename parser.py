#!/usr/bin/python3.4
# -*- coding: utf-8 -*-

import sys, traceback
from urlparse import urljoin
import requests
from parsel import Selector
import re
import json

class DebianParser:
  def __init__(self, url):
    self.url = url
    # Результирующий объект, который будет записан в файл.
    self.result = {}
    # Текущий год в цикле.
    self._current_year = {}

  # Запустить парсер.
  def run(self):
    try:
      self._index = requests.get(self.url)

      years_selector = self._get_years()
      for year_selector in years_selector:
        # Пропускаем шаг, если в ссылке не год.
        if not re.search('href="\d+/"', year_selector):
          continue

        self._set_current_year_obj(year_selector)
        print('Год: {}'.format(self._current_year['text']))

        #if self._current_year['text'] == '2014':
        self._get_current_year_data()
        # Добавляем данные по текущему году в результирующий объект.
        self.result[self._current_year['text']] = self._tmp_arr

      return True
    except Exception as e:
      print('Ошибка: {}'.format(e))
      traceback.print_exc(file=sys.stdout)
      return False

  # Сохранить данные в файл.
  def save_to_file(self):
    print('Запись в файл')
    with open('result.txt', 'w') as file:
        json.dump(self.result, file, indent=2)

  # Получить все года:
  def _get_years(self):
    years_selector = Selector(self._index.text).css('p:contains("The older security advisories are also available:")').extract_first()
    return Selector(years_selector).css('a').extract()

  # Создать временный объект, содержащий ссылку на текущий год и ее наименование.
  def _set_current_year_obj(self, year_selector):
    self._current_year = {}

    match = re.search('<a href="(\d+/?)">(\d+)</a>', year_selector)
    self._current_year['href'] = match.group(1)
    self._current_year['text'] = match.group(2)

  # Получить данные за указанный год.
  def _get_current_year_data(self):
    self.result[self._current_year['text']] = []
    # Временный массив объектов self._tmp_obj, который будет присвоен объекту result[self._current_year['text']]
    self._tmp_arr = []

    # Переходим по ссылке текущего в цикле года.
    year_req = requests.get(self.url + self._current_year['href'])
    advisories = Selector(year_req.text).css('#content strong > a').extract()

    print('Число advisory: {}'.format(len(advisories)))
    count = 0
    # Проходим по списку рекомендаций (advisories) за текущий год.
    for advisory_link in advisories:
      # Временный объект, который будет добавлен в массив self._tmp_arr
      self._tmp_obj = {}

      print count
      count += 1

      self._load_advisory_data(advisory_link)
      self._tmp_arr.append(self._tmp_obj)

  # Загрузить advisory по указанной ссылке в объект self._tmp_obj.
  def _load_advisory_data(self, advisory_link):
    match = re.search('<a href="\./([\w-]+)">(.*?)</a>', advisory_link)
    self._tmp_obj['advisory_id'] = match.group(2)
    print('Advisory id: {}'.format(self._tmp_obj['advisory_id']))

    advisory_req = requests.get(self.url + self._current_year['href'] + match.group(1))
    advisory_content = Selector(advisory_req.text).css('#content')

    self._load_advisory_title(advisory_content)
    self._load_advisory_pub(advisory_content)
    self._load_advisory_affected_packages(advisory_content)
    self._load_advisory_refs(advisory_content)
    self._load_advisory_descr(advisory_content)
    self._load_advisory_criterias(advisory_content)

  # Загрузить advisory_title.
  def _load_advisory_title(self, advisory_content):
    self._tmp_obj['advisory_title'] = advisory_content.xpath('h2/text()').extract_first()
    print('Advisory title: {}'.format(self._tmp_obj['advisory_title']))

  # Загрузить date_of_pub.
  def _load_advisory_pub(self, advisory_content):
    self._tmp_obj['date_of_pub'] = advisory_content.xpath('dl/dt[text()="Date Reported:"]/following-sibling::dd[1]/text()').extract_first()
    print('Advisory date of pub: {}'.format(self._tmp_obj['date_of_pub']))

  # Загрузить affected_packages.
  def _load_advisory_affected_packages(self, advisory_content):
    self._affected_packages = ', '.join(advisory_content.xpath('dl/dt[text()="Affected Packages:"]/following-sibling::dd[1]/a/text()').extract())

  # Загрузить ссылки на CVE.
  def _load_advisory_refs(self, advisory_content):
    self._tmp_obj['refs'] = advisory_content.xpath('dl/dt[text()="Security database references:"]/following-sibling::dd[1]/a/@href').extract()
    print('Advisory refs: {}'.format(self._tmp_obj['refs']))

  # Загрузить description.
  def _load_advisory_descr(self, advisory_content):
    descriptions = advisory_content.xpath('dl/dt[text()="More information:"]/following-sibling::dd[1]//descendant-or-self::*/text()').extract()
    for index, descr_el in enumerate(descriptions):
      if re.search('^((This)|(These).*?(problems?)?.*?(fixed)?.*)|(For the.*)', descr_el):
        descriptions[index] = ''

    # Заменить \n на пробелы, избавиться от мульти-пробелов, преобразовать в utf-8.
    self._tmp_obj['description'] = ' '.join(' '.join(descriptions).replace('\n', ' ').encode('utf-8').split())
    print('Advisory description: {}'.format(self._tmp_obj['description']))

  # Загрузить criterias.
  def _load_advisory_criterias(self, advisory_content):
    self._tmp_obj['criterias'] = []
    # Обработка данных, записанных в формате 2003+ годов.
    criterias_arr_modern_content = advisory_content.xpath('dl/dt[text()="More information:"]/following-sibling::dd[1]/p[starts-with(text(), "For the")]').extract()
    if len(criterias_arr_modern_content) != 0:
      self._processing_modern_criterias(criterias_arr_modern_content)
    else:
      # Обработка данных, записаных ранее 2003 года (формат строк может отличаться).
      criterias_arr_old_content = advisory_content.xpath('dl/dt[text()="More information:"]/following-sibling::dd[1]/p').extract()
      self._processing_old_criterias(criterias_arr_old_content)

  def _processing_modern_criterias(self, criterias_arr_content):
    for criteria in criterias_arr_content:
      # Заменить \n на пробелы, удалить теги, избавиться от мульти-пробелов.
      criteria = self._prepare_criteria(criteria)
      print('Modern criteria string: {}'.format(criteria))

      # В строке может быть несколько предложений. Обрабатывать каждое из них отдельно.
      for str in criteria.split('. '):
        if not re.search('^For the', str):
          continue

        versions = ''

        # Ищем в строке параметры app_ver и dist
        match = re.search('^For the (.*\(.*?\)[\w\s]*)+,? ([\w\s()/,-]*(in version (.*))?)\.?$', str)
        if match:
          if match.group(4):
            versions = re.sub('\.$', '', match.group(4).lstrip())
          elif match.group(3):
            versions = re.sub('\.$', '', match.group(3).lstrip())
          elif match.group(2):
            versions = re.sub('\.$', '', match.group(2).lstrip())
        else:
          # Если по первому шаблону поиск не удался, ищем по второму.
          match = re.search('^For the (.*),? [\w\s()-]*(\d+:?[\w\d\.~\+\-]{4,}.*?)[ \.].*\.?$', str)
          if match and match.group(2):
            versions = match.group(2).lstrip()

        # В одном предложении может быть указано несколько дистрибутивов (например stretch и sid: https://www.debian.org/security/2017/dsa-3796)
        if match and match.group(1):
          dists = re.findall('\((\w+)\)', match.group(1))
        else:
          dists = re.findall('(oldstable|stable|testing distributions), \.?', str)

        # В переменной version сейчас может храниться несколько версий (например: 45.6.0esr-1 of firefox-esr and version 50.1.0-1 of firefox).
        # Нужно их разделить.
        vs = re.findall('\d+:?[\w\d\.~\+\-]{4,}.*?', versions)
        # Если найдены конкретные версии, то в цикле обработать их.
        if len(vs) != 0:
          for version in vs:
            for dist in dists:
              self._set_criteria(dist, version)
        # Если версии не указаны, записать то, что нашлось в match.
        else:
          for dist in dists:
            self._set_criteria(dist, versions)

  def _processing_old_criterias(self, criterias_arr_content):
    for criteria in criterias_arr_content:
      # Заменить \n на пробелы, удалить теги, избавиться от мульти-пробелов.
      criteria = self._prepare_criteria(criteria)
      print('Old criteria string: {}'.format(criteria))

      for str in criteria.split('. '):
        if not re.search('^((This)|(These).*?(problems?)?.*?(fixed)?)', str):
          continue

        data = re.findall('version (\d+:?[\w\d\.~\+\-]{4,}.*?)( for .*?\((.*?)\))?', str)
        for list in data:
          # Если указано несколько версий.
          for version in re.findall('(\d+:?[\w\d\.~\+\-]{4,}.*?)', list[0]):
            self._set_criteria(list[2], version)


  # Заменить \n на пробелы, удалить теги, избавиться от мульти-пробелов.
  def _prepare_criteria(self, criteria):
      return ' '.join(re.sub('<.*?>', '', criteria.replace('\n', ' ').encode('utf-8')).split())

  # Добавить данные в объект self._tmp_obj['criterias']
  def _set_criteria(self, dist, version):
    criteria = {
      'dist': dist,
      'app_title': self._affected_packages,
      'app_ver': version
    }

    self._tmp_obj['criterias'].append(criteria)
    print('Criteria object: {}'.format(criteria))


debian_parser = DebianParser('https://www.debian.org/security/')
if debian_parser.run():
  debian_parser.save_to_file()

