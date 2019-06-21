import { $, browser, by, element } from 'protractor';
// import { protractor } from 'protractor/built/ptor';
import { Helper } from '../helper.po';
import { PageHelper } from '../page-helper.po';

export class BucketsPageHelper extends PageHelper {
  static pages = {
    index: '/#/rgw/bucket',
    create: '/#/rgw/bucket/create'
  };

  static navigateTo(page = null) {
    return browser.get(this.pages[page || 'index']);
  }

  static create(name, owner) {
    this.navigateTo('create');
    expect(PageHelper.getTitleText()).toBe('Create Bucket');

    // Need the string '[value="<owner>"]' to find the owner in dropdown menu
    const str1 = '[value="';
    const str2 = '"]';
    const str3 = str1.concat(owner);
    const getOwnerStr = str3.concat(str2);

    // Enter in bucket name
    element(by.id('bid')).click();
    element(by.id('bid')).sendKeys(name);

    // Select bucket owner
    element(by.id('owner')).click();
    $(getOwnerStr).click();
    expect(element(by.id('owner')).getAttribute('class')).toContain('ng-valid');

    // Click the create button and wait for bucket to be made
    element(by.cssContainingText('button', 'Create Bucket'))
      .click()
      .then(() => {
        browser.sleep(5000);
        this.navigateTo();
        browser.wait(Helper.EC.presenceOf(PageHelper.getTableCell(name)), 10000);
      });
  }

  static edit(name, new_owner) {
    const base_url = '/#/rgw/bucket/edit/';
    const edit_url = base_url.concat(name);
    browser.get(edit_url);

    // Need the string '[value="<owner>"]' to find the new owner in dropdown menu
    const str1 = '[value="';
    const str2 = '"]';
    const str3 = str1.concat(new_owner);
    const getOwnerStr = str3.concat(str2);

    expect(PageHelper.getBreadcrumbText()).toEqual('Edit');

    element(by.id('owner')).click(); // click owner dropdown menu
    $(getOwnerStr).click(); // select the new user
    element(by.cssContainingText('button', 'Edit Bucket'))
      .click()
      .then(() => {
        this.navigateTo();
        browser
          .wait(Helper.EC.elementToBeClickable(PageHelper.getTableCell(name)), 10000)
          .then(() => {
            PageHelper.getTableCell(name).click();
            expect(
              element
                .all(by.css('.table.table-striped.table-bordered'))
                .first()
                .getText()
            ).toMatch(new_owner);
          }); // click edit button and wait to make sure new owner is present in table
      });
  }

  static delete(name) {
    this.navigateTo();

    // wait for table to load
    browser.wait(Helper.EC.elementToBeClickable(PageHelper.getTableCell(name)), 10000);

    PageHelper.getTableCell(name).click(); // click on the bucket you want to delete in the table
    $('.table-actions button.dropdown-toggle').click(); // click toggle menu
    $('li.delete a').click(); // click delete
    // wait for pop-up to be visible (checks for title of pop-up)
    browser
      .wait(Helper.EC.visibilityOf(element(by.css('.modal-title.pull-left'))), 10000)
      .then(() => {
        $('#confirmation').click(); // click confirmation checkbox
        element(by.cssContainingText('button', 'Delete bucket'))
          .click()
          .then(() => {
            this.navigateTo();
            browser.wait(Helper.EC.not(Helper.EC.presenceOf(PageHelper.getTableCell(name))), 10000);
          });
      });
  }

  static invalidCreate() {
    // Types in an invalid name for a bucket
    this.navigateTo('create');
    expect(PageHelper.getTitleText()).toBe('Create Bucket');
    browser.driver
      .manage()
      .window()
      .maximize();
    const nameBox = element(by.id('bid')); // Grabs name box field

    browser.wait(Helper.EC.elementToBeClickable(nameBox), 5000);
    nameBox.click(); // Clicks the Name box on the Create Buckets page
    nameBox.sendKeys('rq');
    browser.sleep(100);
    expect(element(by.id('bid')).getAttribute('class')).toContain('ng-invalid'); // Cehecks for invalid input

    // Chooses 'Select a user' rather than a valid owner on Create Bucket page
    const ownerBox = element(by.id('owner'));
    browser.wait(Helper.EC.elementToBeClickable(ownerBox), 5000);
    ownerBox.click(); // Clicks the Owner drop down on the Create Bucket page
    $('[value="1: null"]').click();
    expect(element(by.id('owner')).getAttribute('class')).toContain('ng-invalid');

    // Clicks the Create Bucket button but the page doesn't move. Done by testing
    // for the breadcrumb and heading
    element(by.cssContainingText('button', 'Create Bucket')).click(); // Clicks Create Bucket button
    expect(PageHelper.getTitleText()).toBe('Create Bucket');
    expect(PageHelper.getBreadcrumbText()).toEqual('Create');
    element(by.cssContainingText('button', 'Cancel')).click();
    nameBox.clear();
  }

  static invalidEdit(name) {
    // Chooses an invalid owner in the Edit Bucket page
    const base_url = '/#/rgw/bucket/edit/';
    const edit_url = base_url.concat(name); // Need to navigate to the page differently
    browser.get(edit_url); // URL is based off of the name of the bucket so it changes
    browser.driver
      .manage()
      .window()
      .maximize();
    expect(PageHelper.getBreadcrumbText()).toEqual('Edit');
    expect(PageHelper.getTitleText()).toBe('Edit Bucket');

    // Chooses 'Select a user' rather than a valid owner on Edit Bucket page
    element(by.id('owner')).click(); // Clicks the Owner drop down on the Edit Bucket page
    $('[value="1: null"]').click();
    expect(element(by.id('owner')).getAttribute('class')).toContain('ng-invalid');

    // Clicks the Edit Bucket button but the page doesn't move. Done by testing for
    // breadcrumb and heading
    expect(element(by.cssContainingText('button', 'Edit Bucket')).getText()).toEqual('Edit Bucket');
    element(by.cssContainingText('button', 'Edit Bucket')).click(); // Gets the Edit button and clicks it
    expect(PageHelper.getBreadcrumbText()).toEqual('Edit');
    expect(PageHelper.getTitleText()).toBe('Edit Bucket');
  }
}
